#!/usr/bin/env python3
"""Build native server packages from a local, verified portable archive.

Requires Python 3.12+, zstd and nFPM. No server compilation is performed.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile


ROOT = Path(__file__).resolve().parents[1]
ARCHES = {'x86_64': ('amd64', 'x86_64'), 'aarch64': ('arm64', 'aarch64')}


def parse_identity(identity):
    match = re.fullmatch(
        r'([1-9][0-9]*)(\.[0-9]+(?:\.[0-9]+)?)(-[a-z]+\.[0-9]+)?'
        r'\+([A-Za-z0-9._]+)',
        identity,
    )
    if not match:
        raise ValueError(f'unsupported portable build identity: {identity}')
    version = identity.split('+', 1)[0].replace('-', '~', 1)
    return match[1], version


def server_build_dependency(identity):
    """A package capability tied to the complete portable build, across repacks."""
    slot, _ = parse_identity(identity)
    digest = hashlib.sha256(identity.encode("ascii")).hexdigest()
    return f"gel-server-{slot}-build-{digest}"


def extract_portable(archive, directory):
    """Unpack a verified zstd tar using Python's path/link safety filter."""
    with tempfile.TemporaryFile() as uncompressed:
        subprocess.run(
            ['zstd', '-d', '-c', str(archive)], stdout=uncompressed, check=True
        )
        uncompressed.seek(0)
        with tarfile.open(fileobj=uncompressed) as source:
            members = source.getmembers()
            members = [
                m for m in members if m.name.rstrip('/') not in {'.', ''}
            ]
            top = {
                member.name.removeprefix('./').split('/')[0]
                for member in members
            }
            if len(top) != 1 or not next(iter(top)).startswith('gel-server-'):
                raise ValueError('expected exactly one portable server tree')
            identity = next(iter(top)).removeprefix('gel-server-')
            parse_identity(identity)
            source.extractall(directory, filter='data')
    tree = Path(directory) / ('gel-server-' + identity)
    if not (tree / 'bin/gel-server').is_file():
        raise ValueError('portable server executable missing')
    return tree


def render_configs(tree, arch, revision, directory):
    if arch not in ARCHES or not re.fullmatch(r'[1-9][0-9]*', revision):
        raise ValueError('unsupported architecture or package revision')
    tree, directory = Path(tree).resolve(), Path(directory).resolve()
    directory.mkdir(parents=True, exist_ok=True)
    identity = tree.name.removeprefix('gel-server-')
    slot, version = parse_identity(identity)
    values = {
        'SLOT': slot,
        'VERSION': version,
        'REVISION': revision,
        'ARCH': ARCHES[arch][0],
        'IDENTITY': identity,
        'SERVER_BUILD': server_build_dependency(identity),
        'TRIPLET': arch + '-linux-gnu',
        'RENDERED_DIR': str(directory),
    }
    for name in [
        'gel-server.nfpm.yaml.in',
        'gel.nfpm.yaml.in',
        'gel-server.service.in',
        'preinstall.sh',
        'postinstall.sh',
        'preremove.sh',
        'postremove.sh',
    ]:
        text = (ROOT / 'packaging/native' / name).read_text()
        for key, value in values.items():
            text = text.replace('@' + key + '@', value)
        target = name.removesuffix('.in')
        if target == 'gel-server.service':
            target = f'gel-server-{slot}.service'
        (directory / target).write_text(text)
    return {
        'slot': slot,
        'version': version,
        'revision': revision,
        'identity': identity,
        'arch': arch,
        'tag': f'pkg-gel-{slot}-{version.replace("~", "-")}-{revision}',
    }


def build(archive, revision, arch, out):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        work = Path(temporary)
        tree = extract_portable(archive, work)
        metadata = render_configs(tree, arch, revision, work / 'rendered')
        environment = os.environ | {
            'PORTABLE_TREE': str(tree),
            'RENDERED_DIR': str(work / 'rendered'),
        }
        for package in ['gel-server', 'gel']:
            for format_, native_arch in zip(['deb', 'rpm'], ARCHES[arch]):
                name = (
                    f'{package}-{metadata["slot"]}-'
                    f'{metadata["version"].replace("~", "-")}-'
                    f'{revision}-{native_arch}.{format_}'
                )
                subprocess.run(
                    [
                        'nfpm',
                        'package',
                        '--config',
                        str(work / 'rendered' / f'{package}.nfpm.yaml'),
                        '--packager',
                        format_,
                        '--target',
                        str(out / name),
                    ],
                    env=environment,
                    check=True,
                )
    (out / f'build-info-{arch}.json').write_text(
        json.dumps(metadata, indent=2) + '\n'
    )
    return metadata


def fetch_cli(arch, out):
    """Fetch the install-test CLI and verify its published digest and size."""
    release = json.loads(
        subprocess.check_output(
            ['gh', 'api', 'repos/gelstable/gel-cli/releases/latest'], text=True
        )
    )
    name = f'gel-cli-{arch}-unknown-linux-musl'
    asset = next(a for a in release['assets'] if a['name'] == name)
    digest = asset.get('digest', '')
    if (
        not isinstance(digest, str)
        or not re.fullmatch(r'sha256:[a-f0-9]{64}', digest)
        or type(asset.get('size')) is not int
        or asset['size'] <= 0
    ):
        raise ValueError('CLI asset requires a SHA256 digest and positive size')
    out.mkdir(parents=True, exist_ok=True)
    binary = out / 'gel'
    subprocess.run(
        [
            'curl',
            '-fL',
            '--retry',
            '3',
            asset['browser_download_url'],
            '-o',
            str(binary),
        ],
        check=True,
    )
    with binary.open('rb') as stream:
        checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
    if binary.stat().st_size != asset['size'] or checksum != digest[7:]:
        raise ValueError('CLI asset size or SHA256 mismatch')
    binary.chmod(0o755)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path)
    parser.add_argument('--revision', default='1')
    parser.add_argument('--arch', choices=ARCHES, required=True)
    parser.add_argument('--out', type=Path, default=Path('dist/native'))
    parser.add_argument('--fetch-cli', action='store_true')
    args = parser.parse_args()
    if args.fetch_cli:
        fetch_cli(args.arch, args.out)
    else:
        if not args.archive:
            parser.error('--archive required')
        print(
            json.dumps(build(args.archive, args.revision, args.arch, args.out))
        )


if __name__ == '__main__':
    main()
