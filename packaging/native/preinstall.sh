#!/bin/bash
set -e
if ! getent group gel > /dev/null; then
    groupadd -r gel
fi
if ! getent passwd gel > /dev/null; then
    useradd -g gel -d /var/lib/gel -s /bin/bash -r -c 'Gel Server' gel
fi
mkdir -p /var/lib/gel
chmod 755 /var/lib/gel
chown gel:gel /var/lib/gel
