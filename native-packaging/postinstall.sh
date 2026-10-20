#!/bin/bash
set -e
if [ -z "${_EDGEDB_INSTALL_SKIP_BOOTSTRAP:-}" ] && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
