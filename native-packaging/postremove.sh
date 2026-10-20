#!/bin/sh
set -e
if { [ "$1" = remove ] || [ "$1" = 0 ]; } && [ -d /run/systemd/system ]; then
    systemctl --system daemon-reload >/dev/null || true
fi
if [ "$1" = purge ] && [ -x /usr/bin/deb-systemd-helper ]; then
    deb-systemd-helper purge 'gel-server-@SLOT@.service' >/dev/null || true
fi
# The gel account and /var/lib/gel are deliberately preserved.
