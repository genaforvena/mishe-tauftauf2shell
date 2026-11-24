#!/bin/sh
# Rebuild all four harness binaries from the pinned upstream tarball.
set -e
cd "$(dirname "$0")" || exit 2

rm -rf src/dsniff-2.5a2 src/dsniff-fixed
tar xzf src/dsniff-2.5a2.tar.gz -C src
cp -a src/dsniff-2.5a2 src/dsniff-fixed
patch -s -p1 -d src/dsniff-fixed < fix-underflow.patch

SRC=src/dsniff-2.5a2
FIX=src/dsniff-fixed
FILES="harness.c decode_sniffer.c base64.c missing/strlcpy.c missing/strlcat.c"
INC="-I. -I$SRC -I$SRC/missing"
INCF="-I. -I$FIX -I$FIX/missing"

build() {
  tree=$1; inc=$2; flags=$3; out=$4
  # shellcheck disable=SC2086
  gcc $flags -g -O0 $inc \
    harness.c "$tree/decode_sniffer.c" "$tree/base64.c" \
    "$tree/missing/strlcpy.c" "$tree/missing/strlcat.c" -o "$out"
}

build "$SRC" "$INC" "-fsanitize=address -fno-omit-frame-pointer" vuln-asan
build "$FIX" "$INCF" "-fsanitize=address -fno-omit-frame-pointer" fixed-asan
build "$SRC" "$INC" "-DGUARDED" vuln-plain
build "$FIX" "$INCF" "-DGUARDED" fixed-plain
echo "bootstrap: 4 binaries built"
