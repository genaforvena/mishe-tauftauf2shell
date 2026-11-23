#!/bin/bash
# Rebuild a pinned/fixed libheif source tree and replay the real-file lane.
# Usage: rebuild_and_run.sh SOURCE_DIR BUILD_DIR OUT_DIR [decode-only|mixed|safe|all]
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
SRC=${1:?source dir}
BUILD=${2:?build dir}
OUT=${3:?output dir}
MODE=${4:-all}
mkdir -p "$OUT"

cmake -S "$SRC" -B "$BUILD" -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF \
  -DWITH_EXAMPLES=ON -DWITH_GDK_PIXBUF=OFF -DWITH_X265=ON \
  -DWITH_JPEG_DECODER=ON -DWITH_JPEG_ENCODER=ON -DWITH_LIBSHARPYUV=OFF \
  -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g' \
  -DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g' \
  -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' >"$OUT/cmake.log" 2>&1 || exit 1
cmake --build "$BUILD" -j2 >"$OUT/build.log" 2>&1 || exit 2

CMD=$(ninja -C "$BUILD" -t commands examples/heif-enc | tail -1)
LIBS=$(printf '%s' "$CMD" | grep -o '/usr/lib[^ ]*' | tr '\n' ' ')
g++ -std=c++17 -g -fsanitize=address -fno-omit-frame-pointer \
  -I"$SRC/libheif/api" -I"$BUILD" "$HERE/reencode_sequence.cc" \
  "$BUILD/libheif/libheif.a" $LIBS -ldl -o "$OUT/driver" || exit 3

INPUT=$HERE/evidence/mixed-mjpeg.heif
run() {
  local label=$1 file=$2; shift 2
  ASAN_OPTIONS=detect_leaks=0 timeout 120 "$OUT/driver" "$file" "$OUT/$label.heif" "$@" \
    >"$OUT/$label.out" 2>&1
  local rc=$?
  echo "$label rc=$rc"
  head -12 "$OUT/$label.out"
}

case "$MODE" in
  decode-only) run decode-only "$INPUT" decode-only ;;
  mixed) run mixed "$INPUT" ;;
  safe) run safe "$HERE/evidence/reference-same-size.heif" ;;
  all) run decode-only "$INPUT" decode-only; run mixed "$INPUT"; run safe "$HERE/evidence/reference-same-size.heif" ;;
  *) echo "unknown mode $MODE" >&2; exit 64 ;;
esac
