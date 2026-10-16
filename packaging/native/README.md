# Native server packages

The reusable `native-packages.yml` workflow accepts `portable-artifact`, an
Actions artifact containing `gel-server-{x86_64,aarch64}-unknown-linux-gnu.tar.zst`,
and optional `revision` (default `1`). It returns the signed packages as the
`native-packages` Actions artifact and does not publish. The caller must run in
a job allowed to use the `package-signing` Environment. That Environment
supplies `PACKAGE_SIGNING_KEY` and `PACKAGE_SIGNING_FPR` to the signing job.
The caller must forward those two named secrets even when their values exist
only in that Environment. It must grant `contents: write` because GitHub
validates the dispatch-only publish job's declaration before evaluating its
condition. The reusable build/sign jobs retain `contents: read`; the caller
path never publishes. After a job uploads the portable artifact, call:

```yaml
jobs:
  native:
    needs: portable
    permissions:
      contents: write
    uses: ./.github/workflows/native-packages.yml
    with:
      portable-artifact: portable-server
    secrets:
      PACKAGE_SIGNING_KEY: ${{ secrets.PACKAGE_SIGNING_KEY }}
      PACKAGE_SIGNING_FPR: ${{ secrets.PACKAGE_SIGNING_FPR }}
```

`portable` is the caller's artifact-uploading job. The signing job receives the
Environment values; no repository-level copies of the signing key are needed.
The caller is responsible for the integrity of its portable artifact.

Manual dispatch accepts `source_tag` and optional `repack`. Shared registry
actions plan the next revision, verify source digests before extraction, sign
RPMs, and publish a validated native-only release. An already packaged release
is a successful no-op unless `repack` is selected. PRs build and install-test
`v7.1` on both architectures without signing or publishing.

`scripts/native_packages.py --archive VERIFIED.tar.zst --arch x86_64 --revision 1`
builds four packages for one architecture from a local verified archive. The
slot and native version come from its top directory. Python 3.12+, zstd and
nFPM are required; `--out` selects the output directory.

The complete portable tree stays under `/usr/lib/gel-server-<slot>/`; both
server command names link to its real binary. The package's native version
removes the portable hash, maps prereleases to `~`, uses epoch 1 and the supplied
revision. The full portable identity remains in its description. Metapackages
require the exact server version plus `gel-cli`. Debian requires `libc6`;
portable bundled libraries replace all distro library dependencies.

The unit is installed disabled. Installation creates the `gel` system user and
its `/var/lib/gel` home with mode 755 and reloads systemd when present. Removal
stops the service, reloads systemd and preserves the account and data. Debian
purge also clears systemd helper state. RPM erase/upgrade numeric arguments are
handled separately from Debian remove/purge arguments.

`install-test.sh deb|rpm ARCH SLOT` runs inside Debian 12 or Rocky 9 with the
packages mounted read-only at `/packages` and a verified matching-architecture
CLI binary at `/cli/gel`. It bootstraps as `gel`, starts a small server, queries
it, stops and removes it, checking that account/data survive. A public key at
`/packages/test-public.asc` is imported to verify signed test RPMs. No private key
is needed by the test. `--fetch-cli --arch ARCH --out DIR` fetches the latest
published CLI binary with API digest/size verification.

## Captured legacy behavior

Captured 2026-09-30 from the Bookworm amd64 Packages index at
`https://packages.geldata.com/apt/dists/bookworm/main/binary-amd64/Packages`,
using the listed SHA256/size and standard `dpkg-deb --field`, `dpkg-deb -e` and
`dpkg-deb -x` on these assets:

- `pool/main/g/gel-server-7/gel-server-7_7.1+08db576-202512051814~bookworm_amd64.deb`
  (42,631,992 bytes;
  `c887c1a4712460602aa4ee0714108b6b9e9c65d236343d8fcdc2c56f3c5fdfda`).
- `pool/main/g/gel-server-7/gel-7_7.1+08db576-202512051814~bookworm_amd64.deb`
  (1,436 bytes;
  `3ea5f9f7df7588d1ea1b92b8ea03b73e19543542c7e5c18b23f063733f29dc0f`).

The server control fields were `Conflicts: edgedb-common`,
`Replaces: edgedb-common, edgedb-server-7 (<< 7.1+08db576-202512051814~bookworm)`
and `Provides: gel-server-catalog (= 202508070002)`. Its Depends contained
tzdata, libuuid1, openssl, libsystemd-dev, zlib1g, libicu72, libc6, libgcc-s1,
libssl3, libstdc++6 and libsystemd0, with distro version constraints. The
metapackage depended on `gel-server-7 (= 7.1+08db576-202512051814~bookworm)` and
`gel-cli`, and carried no scripts.

The legacy unit has `Type=notify`, User/Group gel, `GELDATA=/var/lib/gel/7/data/`,
RuntimeDirectory gel, ExecReload `/bin/kill -HUP ${MAINPID}`, KillMode mixed,
KillSignal SIGINT, TimeoutSec 0 and WantedBy multi-user.target. ExecStart uses
`--data-dir=${GELDATA} --runstate-dir=%t/gel
--tls-cert-mode=generate_self_signed`; only its old
`/usr/lib/x86_64-linux-gnu/gel-server-7/bin/gel-server` path changes to the new
portable tree. Description, documentation URL and network/syslog ordering
remain the same.

Legacy preinst creates the system group/user (`/bin/bash`, home `/var/lib/gel`,
comment `Gel Server`), creates/chmods/chowns that root. Postinst reloads systemd
unless `_EDGEDB_INSTALL_SKIP_BOOTSTRAP` is set. Prerm stops via
deb-systemd-invoke only on remove, with a DPKG_ROOT guard. Postrm reloads on
remove and purges deb-systemd-helper state on purge. None enable/start the unit,
delete data or remove the account. The new scripts retain these behaviors and
adapt the removal arguments to RPM.

Migration uses unversioned Replaces/Obsoletes for `edgedb-common` and
`edgedb-server-<slot>`, plus Conflicts `edgedb-common`. The old catalog Provides
is omitted: extensions use slot compatibility. The distro library constraints
are omitted because the portable tree bundles its dependencies.
