#!/bin/sh
# Offline provisioning for cjose2shell: extract the committed source tarballs,
# apply the single fix hunk to the fixed tree, build jansson and the six
# cjose library variants, verify pins, then build the 8 harness binaries.
# Run from a clean git archive with only deps/*.tar.gz, deps/*.patch and src
# pinned files present. No network and no external systems.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/.." && pwd)
DEPS="$ROOT/deps"
JANSSON="$DEPS/jansson-prefix"

# jansson: static lib + headers, built locally (host has no jansson headers).
rm -rf "$DEPS/jansson-build" "$JANSSON"
mkdir -p "$DEPS/jansson-build/b"
tar xzf "$DEPS/jansson-2.14.tar.gz" -C "$DEPS/jansson-build" --strip-components=1
cd "$DEPS/jansson-build/b"
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_INSTALL_PREFIX="$JANSSON" > /dev/null
cmake --build . -j2 > /dev/null
cmake --install . > /dev/null

extract() { # destination-tree
    d="$ROOT/src/$1"
    rm -rf "$d" && mkdir -p "$d"
    tar xzf "$DEPS/cjose-v0.6.2.4.tar.gz" -C "$d" --strip-components=1
}

for v in vulnerable fixed; do
    extract "$v"
    if [ "$v" = fixed ]; then
        (cd "$ROOT/src/fixed" && patch -p1 --forward < "$DEPS/fix-8c51d245.patch" > /dev/null 2>&1 || true)
        find "$ROOT/src/fixed" \( -name '*.rej' -o -name '*.orig' \) -exec rm -f {} +
    fi
    cp -a "$ROOT/src/$v" "$ROOT/src/clang-$v"
    for cc in gcc clang; do
        extract "plain-$cc-$v"
        if [ "$v" = fixed ]; then
            (cd "$ROOT/src/plain-$cc-$v" && patch -p1 --forward < "$DEPS/fix-8c51d245.patch" > /dev/null 2>&1 || true)
            find "$ROOT/src/plain-$cc-$v" \( -name '*.rej' -o -name '*.orig' \) -exec rm -f {} +
        fi
    done
done

build_lib() { # source-tree compiler cflags
    d="$ROOT/src/$1"
    cd "$d"
    CC="$2" ./configure --with-jansson="$JANSSON" --disable-shared --enable-static \
        CFLAGS="$3" LDFLAGS="$3" > configure.log 2>&1
    make -j2 > build.log 2>&1
}
for v in vulnerable fixed; do
    build_lib "$v" gcc '-g -O0 -fsanitize=address -fno-omit-frame-pointer'
    build_lib "clang-$v" clang '-g -O0 -fsanitize=address -fno-omit-frame-pointer'
    build_lib "plain-gcc-$v" gcc '-g -O0 -fno-omit-frame-pointer'
    build_lib "plain-clang-$v" clang '-g -O0 -fno-omit-frame-pointer'
done

(cd "$ROOT" && sha256sum -c PINS.sha256 > /dev/null)
"$HERE/run.sh"
