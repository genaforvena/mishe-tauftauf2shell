#!/bin/bash
# Loopback-only. Start 6.4.0 jemalloc kresd under gdb, attempt dispatch through
# the F6-overwritten comparator with an active neighbour.
# Usage: run_ksl_active.sh [before|after]
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
MODE="${1:-after}"
LOG="$BASE/harness/ksl-active-${MODE}.txt"
GDBLOG="$BASE/harness/ksl-active-${MODE}-stdout.log"
cp "$BASE/harness/ksl-active.gdb" "$BASE/harness/ksl-active-run.gdb"
sed -i "s|harness/ksl-active.txt|harness/ksl-active-${MODE}.txt|" "$BASE/harness/ksl-active-run.gdb"
: > "$LOG"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
pkill -9 -f 'ksl-active-run.gdb' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/ksl-active-run.gdb" "$KRESD" > "$GDBLOG" 2>&1 &
GB=$!
sleep 8
ss -lun | grep 8855 || echo "no 8855 socket yet"
echo "=== active-neighbour frames mode=$MODE ==="
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_active.py" 8855 "$MODE" 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
echo "=== gdb oracle ==="
cat "$LOG"
echo "=== gdb stdout tail ==="
tail -40 "$GDBLOG"
echo "=== END ==="
