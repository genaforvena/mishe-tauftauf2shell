#!/bin/bash
# Loopback-only. Start 6.4.0 jemalloc kresd under gdb, fire the F6 OOB body
# that overwrites the ngtcp2_ksl comparator, then read the oracle log.
# Usage: run_ksl_control.sh [follow]   (follow = trailing streams after F6)
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
LOG="$BASE/harness/ksl-control.txt"
MODE="${1:-}"
: > "$LOG"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
pkill -9 -f 'ksl-control.gdb' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/ksl-control.gdb" "$KRESD" \
  > "$BASE/harness/ksl-control-stdout.log" 2>&1 &
GB=$!
echo "[runner] gdb pid=$GB mode=$MODE"
sleep 5
echo "=== listener check ==="
ss -lun | grep 8855 || echo "no 8855 socket yet"
echo "=== F6 marker frames (grooms=0, mode=$MODE) ==="
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_marker.py" 8855 $MODE 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
echo "=== ksl-control oracle ==="
cat "$LOG"
echo "=== gdb stdout tail ==="
tail -30 "$BASE/harness/ksl-control-stdout.log"
echo "=== END ==="
