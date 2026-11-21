#!/bin/bash
# php2shell — dom-enabled ASan/UBSan CLI lab build (for CVE-2026-129501).
#
# Usage: bash lab/php2shell/build-dom.sh VERSION   (VERSION = 8.5.12 | 8.5.13)
#
# Builds into lab/build/php-<version>-asan-dom (a copy of the pinned source
# tree, since PHP does not support out-of-tree builds). Produces sapi/cli/php
# with ext/dom + ext/libxml + bundled lexbor enabled. Idempotent: skips
# configure/make when the binary exists. All testing stays local/loopback.

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$SITE/lab/build"

VERSION=$1
[ -n "$VERSION" ] || { echo "usage: $0 VERSION(8.5.12|8.5.13)"; exit 1; }

SRCTREE="$BUILD/php-$VERSION"
[ -d "$SRCTREE" ] || { echo "missing $SRCTREE — run lab/php2shell/provision.sh first"; exit 1; }

export CC=clang
export CFLAGS="-fsanitize=address,undefined -fno-sanitize=function -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g -O1"
export LDFLAGS="-fsanitize=address,undefined"

DEST="$BUILD/php-$VERSION-asan-dom"
if [ ! -d "$DEST" ]; then
    echo "copying source tree to $DEST"
    cp -a "$SRCTREE" "$DEST"
fi

BIN_PHP="$DEST/sapi/cli/php"
if [ ! -x "$BIN_PHP" ]; then
    cd "$DEST"
    ./configure \
        --disable-all \
        --enable-debug \
        --enable-cli \
        --enable-dom \
        --with-libxml \
        --disable-cgi \
        --disable-phpdbg
    make -j"$(nproc)"
fi

echo "$BIN_PHP  $($BIN_PHP -v | head -1)"
echo "$($BIN_PHP -r 'echo "dom=", (int)extension_loaded("dom"), " libxml=", LIBXML_DOTTED_VERSION, "\n";')"
echo "build ok: $DEST"
