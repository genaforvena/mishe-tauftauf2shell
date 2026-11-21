#!/usr/bin/env bash
# Local-only: synthesize a far-end SDP offer, map it to caps with GStreamer's
# own SDP parser, and drive the shipping rtpL16depay set_caps. No networking.
# Run from repo root: bash lab/gst2shell-src/run_sdp.sh
set -u
cd "$(dirname "$0")" || exit 1

CFLAGS="$(pkg-config --cflags gstreamer-1.0 gstreamer-sdp-1.0 gstreamer-rtp-1.0)"
LIBS="$(pkg-config --libs gstreamer-1.0 gstreamer-sdp-1.0 gstreamer-rtp-1.0)"
gcc -g -O0 -Wall $CFLAGS sdp_caps.c -o sdp_caps $LIBS || exit 2
sha256sum sdp_caps.c | sed 's/^/digest /'

echo "=== SDP rtpmap channel-count sweep (timeout 8s each) ==="
for n in 2 8 64 74 86 1000; do
  echo "--- channels=$n ---"
  timeout 8 ./sdp_caps "$n" 2>&1
  printf 'rc=%s\n' "$?"
done

if command -v gdb >/dev/null; then
  echo "=== symbolicated fault, channels=1000 ==="
  DEBUGINFOD_URLS=https://debuginfod.ubuntu.com timeout 120 gdb -q -batch \
    -ex 'set debuginfod enabled on' -ex run -ex 'bt 4' \
    -ex 'x/6i $rip-8' -ex 'info registers rax rbx' \
    --args ./sdp_caps 1000 2>&1 \
    | grep -E 'sdp_rtpmap|caps_from_sdp|SIGSEGV|gst_rtp_L16|gst_pad_set_caps|gstcompat|cmp|mov|rax|rbx|rtpmap|calling real'
else
  echo "gdb absent; backtrace skipped"
fi
