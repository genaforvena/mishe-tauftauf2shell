#!/bin/sh
# Provision the four LibRaw 0.22.3 build trees from pinned artifacts.
# Idempotent: skips a tree whose dcraw_emu binary already exists.
set -eu
cd "$(dirname "$0")"
ROOT=$(pwd)
TAR=pinned/LibRaw-0.22.3.tar.gz
PATCH="$ROOT/pinned/fix-894.patch"
BFLAGS='-O1 -g -I. -w -DUSE_ZLIB'
AFLAGS="$BFLAGS -fsanitize=address -fno-omit-frame-pointer"

build() {
    src=$1; flags=$2; ldadd=$3
    if [ -x "$src/bin/dcraw_emu" ]; then echo "skip $src"; return; fi
    parent=$(dirname "$src")
    if [ ! -d "$src" ]; then
        mkdir -p "$parent"
        tar xzf "$TAR" -C "$parent"
    fi
    if [ "$src" = fixed/LibRaw-0.22.3 ] &&
       ! grep -q 'iwidth = width;' "$src/src/demosaic/misc_demosaic.cpp"; then
        (cd "$src" && patch -p1 < "$PATCH")
    fi
    (cd "$src" && make -j4 -f Makefile.dist bin/dcraw_emu \
        CC=gcc CXX=g++ CFLAGS="$flags" CXXFLAGS="$flags" LDADD="$ldadd")
}

if [ ! -d pinned/LibRaw-0.22.3 ]; then
    tar xzf "$TAR" -C pinned
fi
build pinned/LibRaw-0.22.3 "$AFLAGS" '-lz -fsanitize=address'
build fixed/LibRaw-0.22.3  "$AFLAGS" '-lz -fsanitize=address'
build plain/LibRaw-0.22.3  "$BFLAGS" '-lz'
build o0/LibRaw-0.22.3    '-O0 -g -I. -w -DUSE_ZLIB' '-lz'
echo bootstrap-ok
