#!/bin/bash
# Loopback-only replay: run vulnerable radiusd under read-only gdb, send one
# wire ticket, collect the gdb dump of the _session_ticket() frame.
set -u
cd "$(dirname "$0")"
MODE=${1:-key-known}
PORT=18120
OUT="logs/r4l-$MODE"
export LD_LIBRARY_PATH="$PWD/talloc-prefix/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
rm -f "r4l-gdb-$MODE.log" "r4l-peer-$MODE.out"
gdb -q -batch -x r4l-gdb.cmd ./install/sbin/radiusd > "r4l-gdb-$MODE.log" 2>&1 &
GDBPID=$!
for i in $(seq 1 100); do
  grep -q 'Ready to process requests' "r4l-gdb-$MODE.log" && break
  sleep 0.1
done
python3 peer.py "$MODE" --outdir "$OUT" > "r4l-peer-$MODE.out" 2>&1
for i in $(seq 1 100); do
  kill -0 "$GDBPID" 2>/dev/null || break
  sleep 0.1
done
kill "$GDBPID" 2>/dev/null || true
wait "$GDBPID" 2>/dev/null || true
echo "--- peer ($MODE) ---"
cat "r4l-peer-$MODE.out"
echo "--- gdb R4L ($MODE) ---"
grep -n 'R4L' "r4l-gdb-$MODE.log" || echo "NO R4L LINES"
