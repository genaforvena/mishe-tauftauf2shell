#!/bin/bash
# Drive one real radvdump binary and one crafted RA on loopback only.
# Usage: run_live.sh <binary-path> <attack|ptr|rip|safe> <output-file>
set -u
BIN="$1"; MODE="$2"; OUT="$3"; GDB="${4:-}"
HERE="$(cd "$(dirname "$0")" && pwd)"

sudo -n "$BIN" -d 4 > "$OUT" 2>&1 &
PID=$!
sleep 2
if ! kill -0 "$PID" 2>/dev/null; then
    echo "TARGET_NOT_ALIVE" | tee -a "$OUT"
    exit 2
fi
sudo -n python3 "$HERE/send_ra.py" "$MODE"
sleep 3
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
echo "driver: $BIN mode=$MODE output=$OUT"
