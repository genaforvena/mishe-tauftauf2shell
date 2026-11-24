#!/bin/sh
# Build the WMARKER loopback consumers against the already-pinned cjose libs.
# Plain -no-pie only: ASan stops at the first OOB store; PIE would make the
# fake function table address unstable.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
JANSSON="$ROOT/deps/jansson-prefix"
mkdir -p "$HERE/evidence"

for tree in vulnerable fixed; do
    SRC="$ROOT/src/plain-gcc-$tree"
    [ -f "$SRC/src/.libs/libcjose.a" ] || { echo "missing lib for $tree" >&2; exit 1; }
    gcc -g -O0 -no-pie -fno-omit-frame-pointer -Wall \
        -I"$SRC/include" -I"$SRC/src" -I"$JANSSON/include" \
        "$HERE/server.c" "$SRC/src/.libs/libcjose.a" \
        "$JANSSON/lib/libjansson.a" -lcrypto -lm \
        -o "$HERE/wmarker-$tree"
done
printf 'built wmarker-vulnerable and wmarker-fixed (-no-pie)\n'
