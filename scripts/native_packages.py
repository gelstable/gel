#!/usr/bin/env python3
"""Build native server packages from digest-verified portable releases.

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
import urllib.parse
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
ARCHES = {'x86_64': ('amd64', 'x86_64'), 'aarch64': ('arm64', 'aarch64')}
SAFE = re.compile(r'[A-Za-z0-9._-]+\Z')


def api(path):
    headers = {
        'Accept': 'application/vnd.github+json',
        'X-GitHub-Api-Version': '2022-11-28',
    }
    token = os.environ.get('GH_TOKEN') or os.environ.get('GITHUB_TOKEN')
    if token:
        headers['Authorization'] = f'Bearer {token}'
    request = urllib.request.Request(
        'https://api.github.com/' + path, headers=headers
    )
    with urllib.request.urlopen(request) as response:
        return json.load(response)


def parse_identity(identity):
    match = re.fullmatch(
        r'([1-9][0-9]*)(\.[0-9]+(?:\.[0-9]+)?)(-[a-z]+\.[0-9]+)?'
        r'\+([A-Za-z0-9.]+)',
        identity,
    )
    if not match:
        raise ValueError(f'unsupported portable build identity: {identity}')
    version = identity.split('+', 1)[0].replace('-', '~', 1)
    return match[1], version


def fetch_asset(asset, destination):
    """Verify API byte count and SHA256 before exposing a payload."""
    digest = asset.get('digest')
    size = asset.get('size')
    if not isinstance(digest, str) or not re.fullmatch(
        r'sha256:[a-f0-9]{64}', digest
    ):
        raise ValueError('GitHub asset must have a SHA256 digest')
    if not isinstance(size, int) or size <= 0:
        raise ValueError('GitHub asset must have a positive byte count')
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    def matches(path):
        with path.open('rb') as file:
            checksum = hashlib.file_digest(file, 'sha256').hexdigest()
        return path.stat().st_size == size and checksum == digest[7:]

    if destination.exists() and matches(destination):
        return destination
    temporary = destination.with_suffix(destination.suffix + '.partial')
    try:
        checksum = hashlib.sha256()
        count = 0
        with (
            urllib.request.urlopen(asset['browser_download_url']) as response,
            temporary.open('wb') as output,
        ):
            while chunk := response.read(1024 * 1024):
                count += len(chunk)
                if count > size:
                    raise ValueError('source asset exceeds API byte count')
                checksum.update(chunk)
                output.write(chunk)
        if count != size or checksum.hexdigest() != digest[7:]:
            raise ValueError('source asset size or SHA256 mismatch')
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
    return destination


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


def build(source_tag, channel, revision, arch, out, cache):
    if not SAFE.fullmatch(source_tag) or channel not in {'stable', 'testing'}:
        raise ValueError('invalid source tag or channel')
    release = api(
        'repos/gelstable/gel/releases/tags/'
        + urllib.parse.quote(source_tag, safe='')
    )
    if release['draft']:
        raise ValueError('portable source release is still a draft')
    name = f'gel-server-{arch}-unknown-linux-gnu.tar.zst'
    asset = next(a for a in release['assets'] if a['name'] == name)
    archive = fetch_asset(asset, Path(cache) / name)
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
    metadata.update(
        channel=channel,
        source_tag=source_tag,
        source_sha256=asset['digest'][7:],
        source_size=asset['size'],
    )
    (out / f'build-info-{arch}.json').write_text(
        json.dumps(metadata, indent=2) + '\n'
    )
    return metadata


def manifest(directory, channel, repository='gelstable/gel'):
    """Describe final (signed) package bytes; reject incomplete/mixed builds."""
    if repository != 'gelstable/gel' or channel not in {'stable', 'testing'}:
        raise ValueError('invalid native publisher or channel')
    directory = Path(directory)
    builds = []
    for arch in ARCHES:
        build_info = json.loads(
            (directory / f'build-info-{arch}.json').read_text()
        )
        if build_info.get('arch') != arch:
            raise ValueError(f'build-info-{arch}.json architecture mismatch')
        builds.append(build_info)
    if any(
        b['tag'] != builds[0]['tag'] or b['channel'] != channel for b in builds
    ):
        raise ValueError(
            'architectures must have identical release coordinates'
        )
    tag = builds[0]['tag']
    if not SAFE.fullmatch(tag):
        raise ValueError('unsafe release tag')
    packages = []
    expected = set()
    for build_ in builds:
        for family in ['gel-server', 'gel']:
            for format_, arch in zip(['deb', 'rpm'], ARCHES[build_['arch']]):
                expected.add(
                    f'{family}-{build_["slot"]}-'
                    f'{build_["version"].replace("~", "-")}-'
                    f'{build_["revision"]}-{arch}.{format_}'
                )
    actual = {
        p.name for p in directory.iterdir() if p.suffix in {'.rpm', '.deb'}
    }
    if len(expected) != 8 or actual != expected:
        raise ValueError('expected exactly eight native server/metapackages')
    for name in sorted(expected):
        path = directory / name
        with path.open('rb') as file:
            digest = hashlib.file_digest(file, 'sha256').hexdigest()
        packages.append(
            {
                'url': f'https://github.com/{repository}/releases/download/{tag}/{name}',
                'sha256': digest,
                'size': path.stat().st_size,
            }
        )
    return tag, {
        'schema_version': 2,
        'replacements': [],
        'indexes': [],
        'native': {'channel': channel, 'packages': packages},
    }


def verify_release(tag, manifest_path):
    release = api('repos/gelstable/gel/releases/tags/' + tag)
    assets = {a['name']: a for a in release['assets']}
    data = json.loads(Path(manifest_path).read_text())
    entries = data['native']['packages']
    for package in entries:
        asset = assets[package['url'].rsplit('/', 1)[1]]
        if (
            asset.get('digest') != 'sha256:' + package['sha256']
            or asset['size'] != package['size']
        ):
            raise ValueError(
                'uploaded package digest/size differs from final manifest'
            )
    path = Path(manifest_path)
    asset = assets[path.name]
    with path.open('rb') as file:
        digest = hashlib.file_digest(file, 'sha256').hexdigest()
    if (
        asset.get('digest') != 'sha256:' + digest
        or asset['size'] != path.stat().st_size
    ):
        raise ValueError('uploaded manifest digest/size differs')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source-tag', default='v7.1')
    parser.add_argument(
        '--channel', choices=['stable', 'testing'], default='testing'
    )
    parser.add_argument('--revision', default='1')
    parser.add_argument('--arch', choices=ARCHES)
    parser.add_argument('--out', type=Path, default=Path('dist/native'))
    parser.add_argument('--cache', type=Path, default=Path('.cache/native'))
    parser.add_argument('--manifest', action='store_true')
    parser.add_argument('--verify-release')
    parser.add_argument('--fetch-cli', action='store_true')
    args = parser.parse_args()
    if args.verify_release:
        verify_release(args.verify_release, args.out / 'gel-registry.json')
    elif args.manifest:
        tag, data = manifest(args.out, args.channel)
        (args.out / 'gel-registry.json').write_text(
            json.dumps(data, indent=2) + '\n'
        )
        print(tag)
    elif args.fetch_cli:
        if not args.arch:
            parser.error('--arch required')
        release = api('repos/gelstable/gel-cli/releases/latest')
        name = f'gel-cli-{args.arch}-unknown-linux-musl'
        asset = next(a for a in release['assets'] if a['name'] == name)
        binary = fetch_asset(asset, args.out / 'gel')
        binary.chmod(0o755)
    else:
        for arch in [args.arch] if args.arch else ARCHES:
            print(
                json.dumps(
                    build(
                        args.source_tag,
                        args.channel,
                        args.revision,
                        arch,
                        args.out,
                        args.cache,
                    )
                )
            )


if __name__ == '__main__':
    main()
