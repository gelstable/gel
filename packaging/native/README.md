# Native server packages

`scripts/native_packages.py --source-tag v7.1 --channel testing --revision 1`
fetches both Linux glibc portable assets from `gelstable/gel`. It verifies the
GitHub API's SHA256 digest and byte count before extracting the tarball, then
uses nFPM 2.47.0 to produce architecture-specific server and metapackages.
Python 3.12+, zstd and nFPM must be installed. `--arch x86_64|aarch64`, `--cache`
and `--out` support individual native runners and reusable verified downloads.

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

`sign-rpms.sh DIRECTORY` receives `PACKAGE_SIGNING_KEY` and
`PACKAGE_SIGNING_FPR` only in the protected default-branch signing job. It uses
a temporary private GnuPG home and verifies signatures with an isolated RPM
database containing only the exported public key. `--manifest --out DIR
--channel CHANNEL` requires all eight final packages plus both build-info JSON
files and emits the v2 native-only `gel-registry.json` and safe family tag
`pkg-gel-<slot>-<version>-<revision>`. Digests describe the signed bytes.
`--verify-release TAG --out DIR` checks uploaded packages and manifest against
GitHub asset size/digest fields before publication. A failed draft is retained;
a retry must use a fresh revision rather than overwrite assets.

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
