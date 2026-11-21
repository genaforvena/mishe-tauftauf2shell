#!/usr/bin/env bash
# Local-only reachability test: a loopback RTSP server serves SDP advertising
# a=rtpmap:96 L16/44100/N; a REAL rtspsrc client receives it and links to the
# SHIPPING rtpL16depay. Question: does SDP-derived caps reach set_caps and
# fault the plugin? No external network, no credentials (pre-auth path).
# Run from repo root: bash lab/gst2shell-src/run_rtsp.sh
set -u
cd "$(dirname "$0")" || exit 1
sha256sum rtsp_server.py | sed 's/^/server_digest /'

for spec in "8 18554" "1000 18555"; do
  set -- $spec
  n=$1; port=$2
  echo "=== channels=$n port=$port ==="
  python3 rtsp_server.py "$port" "$n" >"rtsp_server_${n}.log" 2>&1 &
  srvpid=$!
  sleep 0.6
  # rtspsrc is the victim: forced TCP interleaved against our loopback server.
  timeout 12 gst-launch-1.0 -v \
    rtspsrc location="rtsp://127.0.0.1:${port}/" protocols=tcp latency=0 name=src \
    ! rtpL16depay ! fakesink \
    >"rtsp_${n}.log" 2>&1
  rc=$?
  echo "gst-launch rc=$rc"
  kill "$srvpid" 2>/dev/null
  wait "$srvpid" 2>/dev/null
  echo "--- server requests (channels=$n) ---"
  sed 's/^/    /' "rtsp_server_${n}.log"
  echo "--- depay caps / faults (channels=$n) ---"
  grep -E 'rtpL16depay|application/x-rtp|encoding-params|SIGSEGV|segmentation|GST_DEBUG|ERROR|WARNING|setting caps|New clock|PREROLLED|PLAYING' \
    "rtsp_${n}.log" | sed 's/^/    /' | head -40
  echo
done
