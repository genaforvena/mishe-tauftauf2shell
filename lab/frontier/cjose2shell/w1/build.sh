#!/bin/sh
# Build the loopback consumer against the already-pinned cjose libraries.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
JANSSON="$ROOT/deps/jansson-prefix"
mkdir -p "$HERE/evidence"

build_one() {
    out=$1; src=$2; flags=$3; defs=$4
    # shellcheck disable=SC2086
    gcc -g -O0 -fno-omit-frame-pointer -Wall $defs $flags \
        -I"$src/include" -I"$src/src" -I"$JANSSON/include" \
        "$HERE/server.c" "$src/src/.libs/libcjose.a" \
        "$JANSSON/lib/libjansson.a" -lcrypto -lm \
        -o "$HERE/$out"
}

build_one w1-plain-vuln "$ROOT/src/plain-gcc-vulnerable" "" "-DW1_DUMP"
build_one w1-plain-fixed "$ROOT/src/plain-gcc-fixed" "" "-DW1_DUMP"
build_one w1-asan-vuln "$ROOT/src/vulnerable" "-fsanitize=address" ""

# Plain vulnerable build with a static ring of malloc/calloc/realloc callers,
# linked via --wrap so it sees the pinned static cjose library's allocations.
SRC="$ROOT/src/plain-gcc-vulnerable"
gcc -g -O0 -no-pie -fno-omit-frame-pointer -Wall -DW1_DUMP -DW1_ALLOCLOG \
    -I"$SRC/include" -I"$SRC/src" -I"$JANSSON/include" \
    "$HERE/server.c" "$SRC/src/.libs/libcjose.a" \
    "$JANSSON/lib/libjansson.a" \
    -Wl,--wrap=malloc,--wrap=calloc,--wrap=realloc \
    -lcrypto -lm -o "$HERE/w1-trace-vuln"

printf 'built 4 loopback consumers\n'
