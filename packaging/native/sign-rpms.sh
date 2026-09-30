#!/usr/bin/env bash
# Only the signing job receives a private key. Verification trusts its public key alone.
set -euo pipefail
: "${PACKAGE_SIGNING_KEY:?}"
: "${PACKAGE_SIGNING_FPR:?}"
[[ "$PACKAGE_SIGNING_FPR" =~ ^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$ ]]
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export GNUPGHOME="$work/gnupg"
mkdir -m 0700 "$GNUPGHOME"
printf '%s\n' "$PACKAGE_SIGNING_KEY" | gpg --batch --import
unset PACKAGE_SIGNING_KEY
gpg --batch --armor --export "$PACKAGE_SIGNING_FPR" > "$work/public.asc"
test -s "$work/public.asc"
mkdir "$work/rpmdb"
rpmkeys --dbpath "$work/rpmdb" --import "$work/public.asc"
shopt -s nullglob
packages=("${1:?package directory}"/*.rpm)
test "${#packages[@]}" -gt 0
for package in "${packages[@]}"; do
  rpmsign --define "__gpg $(command -v gpg)" --define "_gpg_name $PACKAGE_SIGNING_FPR!" \
    --define "_gpg_path $GNUPGHOME" --define "_gpg_digest_algo sha512" --addsign "$package"
  rpmkeys --dbpath "$work/rpmdb" --checksig --verbose "$package" > "$work/verification"
  cat "$work/verification"
  grep -E '(RSA|DSA).*Signature.*: OK' "$work/verification" > /dev/null
done
