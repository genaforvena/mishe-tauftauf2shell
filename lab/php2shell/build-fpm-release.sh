#!/bin/bash
# php2shell — release (no ZEND_DEBUG) ASan/UBSan FPM build for CVE-2026-129182.
# The vendor phpt forces fast shutdown with ZEND_ASAN_FORCE_FAST_SHUTDOWN=1;
# zend_execute_API.c:455 only honours that env when ZEND_DEBUG is OFF. The
# existing --enable-debug FPM build cannot exercise the vulnerable path.
#
# Usage: bash lab/php2shell/build-fpm-release.sh 8.5.12|8.5.13
# Builds into lab/build/php-<version>-fpm-release-asan. Idempotent.
set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$SITE/lab/build"
VERSION=$1
case "$VERSION" in
    8.5.12|8.5.13) ;;
    *) echo "usage: $0 8.5.12|8.5.13"; exit 1 ;;
esac
SRCTREE="$BUILD/php-$VERSION"
DEST="$BUILD/php-$VERSION-fpm-release-asan"
FPMBIN="$DEST/sapi/fpm/php-fpm"
if [ -x "$FPMBIN" ]; then
    echo "fpm already built: $FPMBIN"
    "$FPMBIN" -v | head -1
    exit 0
fi
[ -d "$SRCTREE" ] || { echo "missing $SRCTREE — run provision.sh first"; exit 1; }
if [ ! -d "$DEST" ]; then
    echo "copying $SRCTREE -> $DEST"
    cp -a "$SRCTREE" "$DEST"
fi
cd "$DEST"
export CC=clang
export CFLAGS="-fsanitize=address,undefined -fno-sanitize=function -fno-omit-frame-pointer -fno-sanitize-recover=undefined -g -O1"
export LDFLAGS="-fsanitize=address,undefined"
echo "=== configure $VERSION fpm release-asan $(date -u) ==="
./configure --disable-all --enable-session --enable-fpm --disable-phpdbg
echo "=== make $VERSION fpm release-asan $(date -u) ==="
make -j2
echo "=== built $VERSION fpm release-asan $(date -u) ==="
"$FPMBIN" -v | head -1
