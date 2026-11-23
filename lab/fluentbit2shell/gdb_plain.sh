#!/usr/bin/env bash
# Inspect saved frame state in a real non-ASan Fluent Bit 5.0.7 flush.
# Loopback only. Usage: gdb_plain.sh <port>
set -u
PORT=$1
HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/evidence"
mkdir -p "$OUT"
CONF="$OUT/gdb-plain.conf"
sed "s/@PORT@/$PORT/" "$HERE/victim.conf.in" > "$CONF"

python3 "$HERE/malicious_forward.py" --port "$PORT" > "$OUT/gdb-plain-server.log" 2>&1 &
SPID=$!
sleep 0.7

gdb -q -batch "${FB_BIN:-./bin-v507-plain}" \
  -ex 'set pagination off' \
  -ex 'break forward.c:568' \
  -ex "run -c $CONF" \
  -ex 'printf "=== HIT forward.c:568 ===\n"' \
  -ex 'bt 5' \
  -ex 'p &msg' \
  -ex 'p/x $rbp' \
  -ex 'p/x $rsp' \
  -ex 'p/x (unsigned long)$rbp - (unsigned long)&msg' \
  -ex 'x/8bx msg+48' \
  -ex 'x/8bx msg+56' \
  -ex 'x/gx $rbp+8' \
  -ex 'x/gx $rbp-8' \
  -ex 'x/72bx msg' \
  -ex 'printf "=== END ===\n"' \
  > "$OUT/gdb-plain.out" 2>&1
GRC=$?

kill -TERM "$SPID" 2>/dev/null || true
wait "$SPID" 2>/dev/null || true
echo "GDB_RC=$GRC"
cat "$OUT/gdb-plain.out"
echo "--- SERVER ---"
cat "$OUT/gdb-plain-server.log"
