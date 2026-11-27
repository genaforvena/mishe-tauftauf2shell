#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
PIN="$ROOT/pins/vuln.tar.gz"
BUILD="$ROOT/build"
JOBS=${JOBS:-4}

for pin in "$PIN" "$ROOT/pins/upstream-fix.tar.gz" "$ROOT/pins/fix.patch" "$ROOT/pins/lexer-fix.patch" "$ROOT/pins/backport-format.patch"; do
    test -f "$pin"
done
mkdir -p "$BUILD"

extract_variant() {
    local name=$1
    local archive=$PIN
    if [[ $name == upstream-fix-* ]]; then
        archive="$ROOT/pins/upstream-fix.tar.gz"
    fi
    rm -rf -- "$BUILD/$name"
    mkdir -p -- "$BUILD/$name"
    tar xzf "$archive" -C "$BUILD/$name" --strip-components=1
    if [[ $name == patched-* ]]; then
        patch -d "$BUILD/$name" -p1 --forward < "$ROOT/pins/lexer-fix.patch"
        patch -d "$BUILD/$name" -p1 --forward < "$ROOT/pins/backport-format.patch"
    fi
}

make_variant() {
    local name=$1 cflags=$2 lflags=$3
    extract_variant "$name"
    make -C "$BUILD/$name" clean >/dev/null
    make -C "$BUILD/$name" -j"$JOBS" CFLAGS="$cflags" LFLAGS="$lflags" \
        LIBS='-lm -lreadline' > "$ROOT/build-$name.log" 2>&1
    cp -- "$BUILD/$name/berry" "$ROOT/berry-$name"
    printf 'BUILD_OK %s\n' "$name"
}

ASAN_CFLAGS='-Wall -std=c99 -O0 -g -fsanitize=address -fno-omit-frame-pointer -DUSE_READLINE_LIB'
PLAIN_CFLAGS='-Wall -std=c99 -O0 -g -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -DUSE_READLINE_LIB'
HARDENED_CFLAGS='-Wall -std=c99 -O2 -g -DUSE_READLINE_LIB'

make_variant vuln-asan "$ASAN_CFLAGS" '-fsanitize=address'
make_variant patched-asan "$ASAN_CFLAGS" '-fsanitize=address'
make_variant vuln-plain "$PLAIN_CFLAGS" ''
make_variant patched-plain "$PLAIN_CFLAGS" ''
make_variant patched-hardened "$HARDENED_CFLAGS" ''
make_variant vuln-hardened "$HARDENED_CFLAGS" ''
make_variant upstream-fix-asan "$ASAN_CFLAGS" '-fsanitize=address'
