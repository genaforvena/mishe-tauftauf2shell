#!/usr/bin/env bash
# Rebuild both pinned libiscsi variants from the tarballs in pins/.
# Builds are in-tree: the out-of-tree libtool link looks for libiscsi.syms
# in the source directory despite generating it in the build directory.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ASAN_FLAGS='-O0 -g -fno-omit-frame-pointer -fsanitize=address -fno-sanitize-recover=all'
PLAIN_FLAGS='-O0 -g -fno-stack-protector -D_FORTIFY_SOURCE=0'

for variant in vuln fixed; do
    for mode in asan plain; do
        src="$ROOT/src-$variant-$mode"
        rm -rf -- "$src"
        mkdir -p -- "$src"
        tar xzf "$ROOT/pins/$variant.tar.gz" -C "$src"
        (cd "$src" && autoreconf -fi > "$ROOT/autoreconf-$variant-$mode.log" 2>&1)
        if [[ $mode == asan ]]; then
            flags=$ASAN_FLAGS
            link='-fsanitize=address'
        else
            flags=$PLAIN_FLAGS
            link=''
        fi
        (cd "$src" && ./configure --disable-werror --disable-manpages \
            --disable-tests --disable-examples --disable-test-tool \
            CFLAGS="$flags" LDFLAGS="$link" \
            > "$ROOT/configure-$variant-$mode.log" 2>&1)
        make -C "$src" -j4 > "$ROOT/build-$variant-$mode.log" 2>&1
        printf 'BUILD_OK %s-%s\n' "$variant" "$mode"
    done
done
