#!/bin/sh
set -e
# Debian remove; RPM final erase is 0 (upgrade removal is 1).
if [ -z "${DPKG_ROOT:-}" ] && { [ "$1" = remove ] || [ "$1" = 0 ]; } && [ -d /run/systemd/system ]; then
    if command -v deb-systemd-invoke >/dev/null 2>&1; then
        deb-systemd-invoke stop 'gel-server-@SLOT@.service' >/dev/null || true
    else
        systemctl stop 'gel-server-@SLOT@.service' >/dev/null || true
    fi
fi
