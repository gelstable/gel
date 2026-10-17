#!/usr/bin/env bash
# Run inside Debian 12 or Rocky Linux 9, with packages at /packages and CLI /cli/gel.
# Usage: install-test.sh deb|rpm amd64|arm64|x86_64|aarch64 SLOT
set -euo pipefail
format="${1:?}"; arch="${2:?}"; slot="${3:?}"
shopt -s nullglob
packages=(/packages/gel-server-"$slot"-*"-$arch.$format")
test "${#packages[@]}" = 1
if [[ "$format" == deb ]]; then
  dpkg -i "${packages[0]}"
  dpkg-query -W "gel-server-$slot"
else
  if [[ -f /packages/test-public.asc ]]; then
    rpm --import /packages/test-public.asc
    rpmkeys --checksig "${packages[0]}"
  fi
  rpm -i "${packages[0]}"
  rpm -q "gel-server-$slot"
fi
getent passwd gel
getent group gel
test "$(stat -c %a /var/lib/gel)" = 755
test "$(stat -c %U:%G /var/lib/gel)" = gel:gel
for command in gel-server edgedb-server; do
  test "$(readlink "/usr/bin/$command-$slot")" = "../lib/gel-server-$slot/bin/gel-server"
done
test -f "/lib/systemd/system/gel-server-$slot.service"
test ! -e "/etc/systemd/system/multi-user.target.wants/gel-server-$slot.service"
# Small explicit pool limits keep the test affordable on emulated local runners.
mkdir -p /run/gel
chown gel:gel /run/gel
case "$arch" in
  amd64|x86_64) triplet=x86_64-linux-gnu ;;
  arm64|aarch64) triplet=aarch64-linux-gnu ;;
esac
# Exercise the path retained in users' full systemd unit overrides.
server="/usr/lib/$triplet/gel-server-$slot/bin/gel-server"
test "$(readlink "$server")" = "../../../gel-server-$slot/bin/gel-server"
args=(--data-dir="/var/lib/gel/$slot/data" --runstate-dir=/run/gel
      --tls-cert-mode=generate_self_signed --max-backend-connections=10
      --compiler-pool-size=1)
runuser -u gel -- "$server" "${args[@]}" --bootstrap-only
setpriv --reuid=gel --regid=gel --init-groups "$server" "${args[@]}" > /tmp/gel-server.log 2>&1 &
pid=$!
cleanup() { kill -INT "$pid" 2>/dev/null || true; wait "$pid" || true; }
trap cleanup EXIT
ready=false
for ((attempt=0; attempt<120; attempt++)); do
  if /cli/gel --admin --unix-path /run/gel query 'SELECT 1 + 1' > /tmp/query.out 2>/tmp/query.err; then
    ready=true
    break
  fi
  if ! kill -0 "$pid" 2>/dev/null; then cat /tmp/gel-server.log; exit 1; fi
  sleep 1
done
if [[ "$ready" != true ]]; then cat /tmp/gel-server.log /tmp/query.err; exit 1; fi
cat /tmp/query.out
grep -qx 2 /tmp/query.out
cleanup
trap - EXIT
test -d "/var/lib/gel/$slot/data"
touch "/var/lib/gel/$slot/data/native-package-preserve"
if [[ "$format" == deb ]]; then
  dpkg --purge "gel-server-$slot"
else
  rpm -e "gel-server-$slot"
fi
getent passwd gel
test -f "/var/lib/gel/$slot/data/native-package-preserve"
test ! -e "$server"
test ! -e "/usr/bin/edgedb-server-$slot"
test ! -e "/lib/systemd/system/gel-server-$slot.service"
echo "Installed, bootstrapped, queried, stopped and removed $format/$arch; account/data preserved"
