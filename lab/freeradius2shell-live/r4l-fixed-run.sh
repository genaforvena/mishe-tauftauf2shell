#!/bin/bash
# Fixed-commit differential: same marker wire ticket against 064567a08f3b.
set -u
cd "$(dirname "$0")"
export LD_LIBRARY_PATH="$PWD/talloc-prefix/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
rm -f r4l-fixed-marker-radiusd.log r4l-fixed-marker-peer.out
./install-fixed/sbin/radiusd -X -d ./install-fixed/etc/raddb \
  -i 127.0.0.1 -p 18122 > r4l-fixed-marker-radiusd.log 2>&1 &
PID=$!
for i in $(seq 1 100); do
  grep -q 'Ready to process requests' r4l-fixed-marker-radiusd.log && break
  sleep 0.1
done
R4L_CANARY=${R4L_CANARY:-fa3871fa3cb7f600} \
R4L_MARKER=${R4L_MARKER:-0x7ffff7fb9140} \
  python3 peer-marker.py key-known --port 18122 \
  --outdir logs/r4l-fixed-marker > r4l-fixed-marker-peer.out 2>&1
sleep 1
echo "--- fixed peer ---"
cat r4l-fixed-marker-peer.out
echo "--- fixed server PAC lines ---"
grep -n 'PAC\|stack smashing\|R4L-LIVE-BENIGN' r4l-fixed-marker-radiusd.log | tail -8
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
