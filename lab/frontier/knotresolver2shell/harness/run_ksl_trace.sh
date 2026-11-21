#!/bin/bash
# Loopback-only: trace post-F6 ksl_insert calls against the corrupted ksl.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
: > "$BASE/harness/ksl-trace.txt"
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
pkill -9 -f 'ksl-trace.gdb' 2>/dev/null
sleep 1
gdb -q -batch -x "$BASE/harness/ksl-trace.gdb" "$KRESD" \
  > "$BASE/harness/ksl-trace-stdout.log" 2>&1 &
GB=$!
sleep 5
"$BASE/poc/venv/bin/python" "$BASE/harness/ksl_marker.py" 8855 follow 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
echo "=== ksl trace ==="
cat "$BASE/harness/ksl-trace.txt"
echo "=== gdb stdout tail ==="
tail -15 "$BASE/harness/ksl-trace-stdout.log"
