#!/bin/sh
# Approximate the schema-restore step of pg_upgrade for a Gel backend.
#
# Usage: upgrade_sim.sh <source-dsn> <target-container>
#
#   <source-dsn>        superuser DSN of the Gel backend on the old major,
#                       reachable from the target container, e.g.
#                       postgres://postgres:postgres@old-pg/postgres
#   <target-container>  docker container running the new major, e.g.
#                       pgvector/pgvector:pg18 (pgvector must be installed,
#                       or ext::pgvector/ext::ai objects fail to restore)
#
# Every Gel database on the source is dumped with the *target's* pg_dump
# (as pg_upgrade does) and restored into a scratch database on the target.
# This is not --binary-upgrade, but it catches the important failure mode:
# views (e.g. the edgedbsql_* emulated catalogs) that reference catalog
# columns which the new major removed.

set -eu
src=$1
tgt=$2
base=${src%/*}

docker exec -i "$tgt" sh -s "$src" "$base" <<'EOF'
src=$1; base=$2
for db in $(psql -At "$src" -c "SELECT datname FROM pg_database WHERE datname LIKE 'E\_%' OR datname LIKE '%\_\_edgedb' ORDER BY 1"); do
    pg_dump --schema-only "$base/$db" | grep -v '^\\\(un\)\?restrict ' > /tmp/schema.sql
    psql -U postgres -qX -c "DROP DATABASE IF EXISTS \"t_$db\"" -c "CREATE DATABASE \"t_$db\""
    psql -U postgres -qX -d "t_$db" -f /tmp/schema.sql > /tmp/restore.log 2>&1 || true
    n=$(grep -c ERROR /tmp/restore.log || true)
    echo "$db: $n errors"
    grep ERROR /tmp/restore.log | head -12 || true
done
EOF
