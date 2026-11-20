#!/usr/bin/env bash
# Build standalone decoder harness against a given brotli source tag.
# Usage: ./build.sh v1.2.0|v1.2.1 [asan|plain]
set -euo pipefail
TAG="${1:?usage: ./build.sh v1.2.0|v1.2.1 [asan|plain]}"
MODE="${2:-asan}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$HERE/brotli-src"
OUT="$HERE/build-$TAG-$MODE"
mkdir -p "$OUT"
cd "$SRC"
git checkout --quiet "$TAG"
INC="-I$SRC/c/include -I$SRC/c/dec -I$SRC/c/common"
SRCS="$(printf '%s ' "$SRC"/c/dec/*.c "$SRC"/c/common/*.c)"
if [ "$MODE" = "asan" ]; then
  CC="clang -fsanitize=address -fno-omit-frame-pointer -g -O1 -Wall"
else
  CC="gcc -g -O1 -Wall"
fi
# shellcheck disable=SC2086
$CC $INC "$HERE/decoder_harness.c" $SRCS -lm -o "$OUT/decoder_harness"
echo "built $OUT/decoder_harness ($TAG, $MODE)"
