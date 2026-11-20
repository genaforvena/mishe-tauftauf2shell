#!/bin/bash
# php2shell — build the FPM SAPI with the same ASan+UBSan flags as the cli/cgi
# lab builds, for the FPM lane prescribed in owner DM #64.
#
# Usage: bash lab/php2shell/build-fpm.sh [8.4.26|8.4.27|all]
#   Builds lab/build/php-<version>-fpm-asan from the pristine pinned source at
#   lab/build/php-<version>. Produces sapi/fpm/php-fpm. Idempotent.
#
# Evidence notes (same as build.sh):
# - ASAN_OPTIONS=...detect_leaks=0 at RUN time (PHP "leaks" by design on fatal).
# - --enable-debug turns on ZEND_DEBUG asserts; label every result with it.
# - --enable-fpm uses FPM's own epoll event loop (no libevent needed on Linux).

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$SITE/lab/build"

build_one() {
    local VERSION=$1
    local SRCTREE="$BUILD/php-$VERSION"
    local DEST="$BUILD/php-$VERSION-fpm-asan"
    local FPMBIN="$DEST/sapi/fpm/php-fpm"
    if [ -x "$FPMBIN" ]; then
        echo "fpm already built: $FPMBIN"
        "$FPMBIN" -v | head -1
        return
    fi
    [ -d "$SRCTREE" ] || { echo "missing $SRCTREE"; exit 1; }
    if [ ! -d "$DEST" ]; then
        echo "copying $SRCTREE -> $DEST"
        cp -a "$SRCTREE" "$DEST"
    fi
    cd "$DEST"
    export CC=clang
    export CFLAGS="-fsanitize=address,undefined -fno-sanitize=function -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g -O1"
    export LDFLAGS="-fsanitize=address,undefined"
    echo "=== configure $VERSION fpm $(date -u) ==="
    ./configure \
        --disable-all \
        --enable-debug \
        --enable-session \
        --enable-fpm \
        --disable-phpdbg
    echo "=== make $VERSION fpm $(date -u) ==="
    make -j2
    echo "=== built $VERSION fpm $(date -u) ==="
    "$FPMBIN" -v | head -1
}

case "${1:-all}" in
    8.4.26|8.4.27) build_one "$1" ;;
    all) build_one 8.4.26; build_one 8.4.27 ;;
    *) echo "usage: $0 [8.4.26|8.4.27|all]"; exit 1 ;;
esac
