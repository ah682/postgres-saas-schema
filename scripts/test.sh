#!/usr/bin/env bash
# A fresh private cluster, never the host's PostgreSQL service/database.
set -euo pipefail
repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
pg_bin=${PG_BIN:-$(pg_config --bindir)}
for binary in initdb pg_ctl psql; do
    if [[ ! -x "$pg_bin/$binary" ]]; then
        echo "Missing PostgreSQL server/client binary: $pg_bin/$binary (set PG_BIN)" >&2
        exit 1
    fi
done
export PATH="$pg_bin:$PATH"
cluster=$(mktemp -d /tmp/saas-schema-test.XXXXXX)
cleanup() {
    pg_ctl -D "$cluster/data" -m immediate -w stop >/dev/null 2>&1 || true
    rm -rf -- "$cluster"
}
trap cleanup EXIT
mkdir "$cluster/socket"
initdb -D "$cluster/data" -A trust -U postgres --no-locale >/dev/null
pg_ctl -D "$cluster/data" -l "$cluster/server.log" \
    -o "-k $cluster/socket -c listen_addresses=''" -w start >/dev/null || {
    cat "$cluster/server.log" >&2
    exit 1
}
export PGHOST="$cluster/socket" PGPORT=5432 PGUSER=postgres PGDATABASE=postgres
# An empty PGSERVICE is a real service name to libpq, not a reset. Remove
# inherited service/address/options settings so only this private socket is used.
unset PGSERVICE PGSERVICEFILE PGHOSTADDR PGOPTIONS
export PGCONNECT_TIMEOUT=5
psql -X -v ON_ERROR_STOP=1 -q -f "$repo/schema.sql" >/dev/null
psql -X -v ON_ERROR_STOP=1 -q -f "$repo/bootstrap.sql" >/dev/null
# Test an actual authenticated login which may SET ROLE only to saas_app.
psql -X -v ON_ERROR_STOP=1 -q <<'SQL'
CREATE ROLE saas_test_login LOGIN NOINHERIT NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT saas_app TO saas_test_login;
SQL
python3 "$repo/tests/test_contract.py"
