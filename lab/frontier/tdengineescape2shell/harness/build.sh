#!/bin/sh
# Build the pinned trimString excerpts in caller-shaped stack frames. Local only.
set -eu
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS >/dev/null
mkdir -p bin
VULN='"pins/parUtil-trimString-vuln.inc"'
FIXED='"pins/parUtil-trimString-fixed.inc"'
build() {
    cc=$1; arm=$2; inc=$3; shift 3
    "$cc" -O0 -g -I. -DTRIM_SOURCE="$inc" "$@" harness/driver.c -o "bin/$arm"
}
build cc vuln-asan-gcc "$VULN" -fsanitize=address
build clang vuln-asan-clang "$VULN" -fsanitize=address
build cc fixed-asan-gcc "$FIXED" -fsanitize=address
build cc vuln-plain-gcc "$VULN"
echo BUILD_OK
