#!/bin/bash
# php2shell build — ASan/UBSan (or plain) lab build of a provisioned PHP tree.
#
# Usage: bash lab/php2shell/build.sh VERSION MODE
#   VERSION  8.4.26 (affected) | 8.4.27 (fixed)
#   MODE     asan | plain
#
# Builds into lab/build/php-<version>-<mode> (a copy of the source tree, since
# PHP does not support out-of-tree builds). Produces sapi/cli/php and
# sapi/cgi/php-cgi. Idempotent: skips configure/make when the binaries exist.
#
# Notes that matter for evidence:
# - ASAN_OPTIONS=...detect_leaks=0 (PHP "leaks" by design at fatal-exit time).
# - Runtime: export USE_ZEND_ALLOC=0 to route every emalloc to libc malloc so
#   ASan sees request-memory UAF/stale-state reads per allocation. With the
#   stock ZEND allocator, request memory is pooled and freed wholesale, which
#   hides cross-request/stale-state reads from ASan.
# - --enable-debug (ZEND_DEBUG) turns on allocator bookkeeping and ZEND_ASSERTs;
#   every rung claim must be labeled with this build configuration.

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$SITE/lab/build"

VERSION=$1
MODE=$2
[ -n "$VERSION" ] && [ -n "$MODE" ] || { echo "usage: $0 VERSION(8.4.26|8.4.27) MODE(asan|plain)"; exit 1; }

SRCTREE="$BUILD/php-$VERSION"
[ -d "$SRCTREE" ] || { echo "missing $SRCTREE — run lab/php2shell/provision.sh first"; exit 1; }

case "$MODE" in
asan)
    export CC=clang
    export CFLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g -O1"
    export LDFLAGS="-fsanitize=address,undefined"
    ;;
plain)
    export CC=gcc
    export CFLAGS="-g -O2"
    unset LDFLAGS
    ;;
*) echo "MODE must be asan|plain"; exit 1;;
esac

DEST="$BUILD/php-$VERSION-$MODE"
if [ ! -d "$DEST" ]; then
    echo "copying source tree to $DEST"
    cp -a "$SRCTREE" "$DEST"
fi

BIN_PHP="$DEST/sapi/cli/php"
BIN_CGI="$DEST/sapi/cgi/php-cgi"

if [ ! -x "$BIN_PHP" ] || [ ! -x "$BIN_CGI" ]; then
    cd "$DEST"
    ./configure \
        --disable-all \
        --enable-debug \
        --enable-session \
        --enable-cgi \
        --disable-phpdbg
    make -j"$(nproc)"
fi

echo "$BIN_PHP  $($BIN_PHP -v | head -1)"
echo "$BIN_CGI  $($BIN_CGI -v | head -1)"
echo "build ok: $DEST"
