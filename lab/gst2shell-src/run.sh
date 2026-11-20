#!/usr/bin/env bash
# Rebuild and run the source-faithful GStreamer rtpL16depay layout probe.
# This is NOT a live GStreamer build: it reproduces the exact tail field
# layout read from the pinned vulnerable commit 0b70c356... so the OOB write's
# real landing zones can be classified. Prints evidence, always exits 0;
# inspect the text, do not treat exit status as a grade.
set -u
cd "$(dirname "$0")" || exit 2
CC=${CC:-gcc}

echo "=== pinned source digests (fetched under upstream/, gitignored) ==="
sha256sum upstream/* 2>/dev/null

echo "=== compile ==="
$CC -O0 -g -Wall -Wextra -o layout_probe layout_probe.c || exit 2
$CC -O0 -g -Wall -Wextra -fsanitize=address -fno-omit-frame-pointer \
  -o layout_probe_asan layout_probe.c || exit 2
sha256sum layout_probe.c

echo "=== non-ASan: channels=1000, 64 KiB backing (zone counts) ==="
./layout_probe 1000 big

echo "=== non-ASan: channels=74, 64 KiB backing (partial) ==="
./layout_probe 74 big

echo "=== ASan: channels=1000, exact 328-byte element-tail allocation ==="
r=$(mktemp)
ASAN_OPTIONS=detect_leaks=0 ./layout_probe_asan 1000 >"$r" 2>&1
echo "asan exit=$?"
grep -E 'ERROR: AddressSanitizer|WRITE of size|located 0 bytes after|SUMMARY: AddressSanitizer' "$r" | head -6
rm -f "$r"
