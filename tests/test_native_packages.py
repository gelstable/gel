import hashlib
import io
import json
import os
import importlib.util
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import unittest
from unittest import mock


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

    def test_download_verification(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / 'source'
            source.write_bytes(b'portable server')
            asset = {
                'browser_download_url': source.as_uri(),
                'size': 15,
                'digest': 'sha256:'
                + hashlib.sha256(source.read_bytes()).hexdigest(),
            }
            result = self.native.fetch_asset(asset, root / 'cached')
            self.assertEqual(result.read_bytes(), source.read_bytes())
            for change in [
                {'size': 14},
                {'digest': 'sha256:' + '0' * 64},
                {'digest': None},
            ]:
                with self.subTest(change=change), self.assertRaises(ValueError):
                    self.native.fetch_asset(asset | change, root / 'bad')
                self.assertFalse((root / 'bad').exists())

    @unittest.skipUnless(
        all(shutil.which(tool) for tool in ['nfpm', 'dpkg-deb', 'rpm']),
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
                self.native.render_configs(tree, 'x86_64', '1', out)
                environment = os.environ | {
                    'PORTABLE_TREE': str(tree),
                    'RENDERED_DIR': str(out),
                }
                for family in ['gel-server', 'gel']:
                    for format_ in ['deb', 'rpm']:
                        package = out / f'{family}.{format_}'
                        subprocess.run(
                            [
                                'nfpm',
                                'package',
                                '--config',
                                str(out / f'{family}.nfpm.yaml'),
                                '--packager',
                                format_,
                                '--target',
                                str(package),
                            ],
                            env=environment,
                            check=True,
                            capture_output=True,
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
                                ],
                                text=True,
                            )
                            self.assertIn(f'Version: 1:{version}-1', result)
                            self.assertIn('Architecture: amd64', result)
                            dependency = (
                                f'gel-server-7 (= 1:{version}-1), gel-cli'
                                if family == 'gel'
                                else 'libc6'
                            )
                            self.assertIn('Depends: ' + dependency, result)
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
                                result, f'{family}-7 1:{version}-1 x86_64'
                            )
                            requirements = subprocess.check_output(
                                ['rpm', '-qp', '--requires', str(package)],
                                text=True,
                            ).splitlines()
                            self.assertEqual(
                                requirements,
                                [f'gel-server-7 = 1:{version}-1', 'gel-cli']
                                if family == 'gel'
                                else [],
                            )

    def test_manifest_uses_final_bytes_and_requires_complete_pair(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            for arch, names in self.native.ARCHES.items():
                tree = out / 'gel-server-7.2-rc.1+abc'
                tree.mkdir(exist_ok=True)
                info = self.native.render_configs(tree, arch, '2', out / arch)
                info['channel'] = 'testing'
                (out / f'build-info-{arch}.json').write_text(json.dumps(info))
                for family in ['gel-server', 'gel']:
                    for format_, name in zip(['deb', 'rpm'], names):
                        (
                            out / f'{family}-7-7.2-rc.1-2-{name}.{format_}'
                        ).write_bytes(b'unsigned')
            rpm = out / 'gel-server-7-7.2-rc.1-2-aarch64.rpm'
            rpm.write_bytes(b'final signed bytes')
            tag, manifest = self.native.manifest(out, 'testing')
            self.assertEqual(tag, 'pkg-gel-7-7.2-rc.1-2')
            self.assertEqual(manifest['schema_version'], 2)
            self.assertEqual(manifest['indexes'], [])
            self.assertEqual(len(manifest['native']['packages']), 8)
            entry = next(
                p
                for p in manifest['native']['packages']
                if p['url'].endswith(rpm.name)
            )
            self.assertEqual(entry['size'], rpm.stat().st_size)
            self.assertEqual(
                entry['sha256'], hashlib.sha256(rpm.read_bytes()).hexdigest()
            )
            manifest_path = out / 'gel-registry.json'
            manifest_path.write_text(json.dumps(manifest))
            assets = []
            for path in (
                list(out.glob('*.deb'))
                + list(out.glob('*.rpm'))
                + [manifest_path]
            ):
                assets.append(
                    {
                        'name': path.name,
                        'size': path.stat().st_size,
                        'digest': 'sha256:'
                        + hashlib.sha256(path.read_bytes()).hexdigest(),
                    }
                )
            with mock.patch.object(
                self.native, 'api', return_value={'assets': assets}
            ):
                self.native.verify_release(tag, manifest_path)
                assets[0]['size'] += 1
                with self.assertRaises(ValueError):
                    self.native.verify_release(tag, manifest_path)
                assets[0]['size'] -= 1
                assets[-1]['digest'] = 'sha256:' + '0' * 64
                with self.assertRaises(ValueError):
                    self.native.verify_release(tag, manifest_path)
            rpm.unlink()
            with self.assertRaises(ValueError):
                self.native.manifest(out, 'testing')

    def test_manifest_rejects_duplicate_architecture_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d)
            tree = out / 'gel-server-7.1+abc'
            tree.mkdir()
            info = self.native.render_configs(tree, 'x86_64', '1', out)
            info['channel'] = 'testing'
            # Inconsistent arm metadata used to collapse the expected set
            # to four files, allowing an incomplete release manifest.
            for arch in self.native.ARCHES:
                (out / f'build-info-{arch}.json').write_text(json.dumps(info))
            for family in ['gel-server', 'gel']:
                for format_, arch in zip(
                    ['deb', 'rpm'], self.native.ARCHES['x86_64']
                ):
                    (out / f'{family}-7-7.1-1-{arch}.{format_}').write_bytes(
                        b'package bytes'
                    )
            with self.assertRaisesRegex(ValueError, 'architecture'):
                self.native.manifest(out, 'testing')

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
