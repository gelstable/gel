import io
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class NativePackagesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            'native_packages', ROOT / 'scripts/native_packages.py'
        )
        cls.native = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.native)

    def test_versions_and_config(self):
        for identity, expected in [
            ('7.1+ec15259', '7.1'),
            ('7.1+gec15259.cv2025_20261017', '7.1'),
            ('7.2-rc.1+abc', '7.2~rc.1'),
        ]:
            with (
                self.subTest(identity=identity),
                tempfile.TemporaryDirectory() as d,
            ):
                out = Path(d)
                tree = out / ('gel-server-' + identity)
                tree.mkdir()
                result = self.native.render_configs(tree, 'x86_64', '1', out)
                self.assertEqual(result['version'], expected)
                self.assertEqual(result['slot'], '7')
                text = (out / 'gel.nfpm.yaml').read_text()
                self.assertIn(f'gel-server-7 (= 1:{expected}-1)', text)
                self.assertIn(f'gel-server-7 = 1:{expected}-1', text)
                self.assertIn(identity, text)
                server = (out / 'gel-server.nfpm.yaml').read_text()
                self.assertIn('type: tree', server)
                self.assertIn('/usr/lib/gel-server-7/', server)
                self.assertNotIn('libsystemd-dev', server)
                self.assertIn(self.native.server_build_dependency(identity), server)
                self.assertIn('/usr/lib/x86_64-linux-gnu/gel-server-7', server)

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ['nfpm', 'dpkg-deb', 'rpm', 'zstd']),
        'Linux packaging tools required',
    )
    def test_real_package_headers_for_final_and_prerelease(self):
        for identity, version in [
            ('7.1+ec15259', '7.1'),
            ('7.2-rc.1+abc', '7.2~rc.1'),
        ]:
            with (
                self.subTest(identity=identity),
                tempfile.TemporaryDirectory() as d,
            ):
                out = Path(d)
                tree = out / ('gel-server-' + identity)
                (tree / 'bin').mkdir(parents=True)
                (tree / 'bin/gel-server').write_text('#!/bin/sh\nexit 0\n')
                (tree / 'bin/gel-server').chmod(0o755)
                archive = out / 'portable.tar'
                with tarfile.open(archive, 'w') as source:
                    source.add(tree, arcname=tree.name)
                subprocess.run(['zstd', '-q', str(archive)], check=True)
                packages = out / 'packages'
                metadata = self.native.build(
                    out / 'portable.tar.zst', '3', 'x86_64', packages
                )
                self.assertEqual(metadata['version'], version)
                self.assertEqual(metadata['slot'], '7')
                self.assertEqual(len(list(packages.glob('*.deb'))), 2)
                self.assertEqual(len(list(packages.glob('*.rpm'))), 2)
                for family in ['gel-server', 'gel']:
                    for format_, arch in [('deb', 'amd64'), ('rpm', 'x86_64')]:
                        package = packages / (
                            f'{family}-7-{version.replace("~", "-")}-3-'
                            f'{arch}.{format_}'
                        )
                        if format_ == 'deb':
                            result = subprocess.check_output(
                                [
                                    'dpkg-deb',
                                    '--field',
                                    str(package),
                                    'Package',
                                    'Version',
                                    'Architecture',
                                    'Depends',
                                    'Provides',
                                ],
                                text=True,
                            )
                            self.assertIn(f'Version: 1:{version}-3', result)
                            self.assertIn('Architecture: amd64', result)
                            dependency = (
                                f'gel-server-7 (= 1:{version}-3), gel-cli'
                                if family == 'gel'
                                else 'libc6'
                            )
                            self.assertIn('Depends: ' + dependency, result)
                            if family == 'gel-server':
                                self.assertIn('Provides: ' + self.native.server_build_dependency(identity), result)
                                extracted = out / 'extracted'
                                subprocess.run(['dpkg-deb', '-x', str(package), str(extracted)], check=True)
                                self.assertFalse((extracted / 'usr/lib64/gel-server-7').exists())
                                self.assertEqual(
                                    (extracted / 'usr/lib/x86_64-linux-gnu/gel-server-7/bin/gel-server').read_text(),
                                    '#!/bin/sh\nexit 0\n',
                                )
                        else:
                            result = subprocess.check_output(
                                [
                                    'rpm',
                                    '-qp',
                                    '--qf',
                                    '%{NAME} %{EPOCH}:%{VERSION}-%{RELEASE} '
                                    '%{ARCH}',
                                    str(package),
                                ],
                                text=True,
                            )
                            self.assertEqual(
                                result, f'{family}-7 1:{version}-3 x86_64'
                            )
                            if family == 'gel-server':
                                files = subprocess.check_output(
                                    ['rpm', '-qpl', str(package)], text=True
                                ).splitlines()
                                self.assertIn('/usr/lib64/gel-server-7/bin/gel-server', files)
                                self.assertFalse(any('/x86_64-linux-gnu/' in path for path in files))
                            requirements = subprocess.check_output(
                                ['rpm', '-qp', '--requires', str(package)],
                                text=True,
                            ).splitlines()
                            self.assertEqual(
                                requirements,
                                [f'gel-server-7 = 1:{version}-3', 'gel-cli']
                                if family == 'gel'
                                else [],
                            )

    @unittest.skipUnless(shutil.which('zstd'), 'zstd required')
    def test_archive_root_marker_and_unsafe_paths(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            tar = out / 'source.tar'
            with tarfile.open(tar, 'w') as source:
                marker = tarfile.TarInfo('./')
                marker.type = tarfile.DIRTYPE
                source.addfile(marker)
                binary = tarfile.TarInfo('gel-server-7.1+abc/bin/gel-server')
                binary.size = 5
                source.addfile(binary, io.BytesIO(b'hello'))
            subprocess.run(['zstd', '-q', str(tar)], check=True)
            result = self.native.extract_portable(
                out / 'source.tar.zst', out / 'safe'
            )
            self.assertEqual((result / 'bin/gel-server').read_bytes(), b'hello')
            with tarfile.open(tar, 'w') as source:
                malicious = tarfile.TarInfo('gel-server-7.1+abc/../../escaped')
                source.addfile(malicious)
            subprocess.run(['zstd', '-q', '-f', str(tar)], check=True)
            with self.assertRaises(tarfile.FilterError):
                self.native.extract_portable(
                    out / 'source.tar.zst', out / 'unsafe'
                )
            self.assertFalse((out / 'escaped').exists())

    def test_reject_invalid_identity(self):
        for identity in ['7.1', '7.1+hash/../bad', 'hello+abc']:
            with self.subTest(identity=identity), self.assertRaises(ValueError):
                self.native.parse_identity(identity)

    @unittest.skipUnless(shutil.which('dpkg'), 'dpkg required')
    def test_dpkg_ordering(self):
        subprocess.run(
            [
                'dpkg',
                '--compare-versions',
                '1:7.1-1',
                'gt',
                '7.1+08db576-202512051814~bookworm',
            ],
            check=True,
        )
        subprocess.run(
            ['dpkg', '--compare-versions', '1:7.2~rc.1-1', 'lt', '1:7.2-1'],
            check=True,
        )

    @unittest.skipUnless(shutil.which('rpmdev-vercmp'), 'rpmdevtools required')
    def test_rpm_ordering(self):
        for left, right, relation in [
            ('1:7.1-1', '7.1+08db576-202512051814~bookworm', '>'),
            ('1:7.2~rc.1-1', '1:7.2-1', '<'),
        ]:
            result = subprocess.run(
                ['rpmdev-vercmp', left, right], capture_output=True, text=True
            )
            self.assertIn(f'{left} {relation} {right}', result.stdout)


if __name__ == '__main__':
    unittest.main()
