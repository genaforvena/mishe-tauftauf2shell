#!/usr/bin/env bash
# Drive the SHIPPING rtpL16depay plugin with a far-end encoding-params caps
# value. Local process only; no network, no external target.
# Run from repo root: bash lab/gst2shell-src/run_real.sh
set -u
cd "$(dirname "$0")" || exit 1

command -v gst-inspect-1.0 >/dev/null || { echo NO_GSTREAMER; exit 2; }
gst-inspect-1.0 rtpL16depay >/dev/null 2>&1 || { echo NO_RTPL16DEPAY; exit 2; }
gst-inspect-1.0 rtpL16depay 2>&1 | grep -m1 'Filename' || true

CFLAGS="$(pkg-config --cflags gstreamer-1.0 gstreamer-rtp-1.0)"
LIBS="$(pkg-config --libs gstreamer-1.0 gstreamer-rtp-1.0)"
gcc -g -O0 -Wall $CFLAGS real_plugin.c -o real_plugin $LIBS || exit 2
sha256sum real_plugin.c | sed 's/^/digest /'

echo "=== single-field caps sweep (timeout 8s each) ==="
for n in 8 64 74 84 85 86 87 88 100 200 1000; do
  timeout 8 ./real_plugin "$n" >/dev/null 2>&1
  printf 'channels=%-5s rc=%s\n' "$n" "$?"
done

if command -v gdb >/dev/null; then
  echo "=== gdb backtrace, channels=1000 ==="
  gdb -q -batch -ex run -ex 'bt 6' -ex 'info registers rax rip' \
    --args ./real_plugin 1000 2>&1 | grep -E 'SIGSEGV|libgstrtp|libgstreamer|gst_pad_set_caps|real_plugin.c|^rax|^rip'
  echo "=== gdb backtrace, channels=86 ==="
  gdb -q -batch -ex run -ex 'bt 6' \
    --args ./real_plugin 86 2>&1 | grep -E 'SIGSEGV|libc|arena|__libc_free|real_plugin.c'
else
  echo "gdb absent; backtraces skipped"
fi
