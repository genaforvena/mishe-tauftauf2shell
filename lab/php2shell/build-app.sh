#!/bin/bash
# php2shell — build a full-featured, release-like PHP 8.4.27 (CLI + FPM, no
# ASan, no --enable-debug) to host a REAL web application for the rung-5
# lane (CVE-2026-126714 splice -> real-app session decode -> unserialize
# gadget). The harness FPM builds are --disable-all; a real app needs
# dom/xml/mbstring/pdo_sqlite/session and friends.
#
# Usage: bash lab/php2shell/build-app.sh [8.4.27]
#   Produces lab/build/php-<version>-app/{sapi/cli/php,sapi/fpm/php-fpm}.
#   Source is re-extracted from the sha256-pinned tarball in lab/src/.

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
VERSION=${1:-8.4.27}
SRC="$SITE/lab/src/php-$VERSION.tar.xz"
BUILD="$SITE/lab/build"
DEST="$BUILD/php-$VERSION-app"
CLIBIN="$DEST/sapi/cli/php"
FPMBIN="$DEST/sapi/fpm/php-fpm"

[ -f "$SRC" ] || { echo "missing pinned tarball $SRC"; exit 1; }
if [ -x "$CLIBIN" ] && [ -x "$FPMBIN" ]; then
    echo "app build already present: $DEST"
    "$CLIBIN" -v | head -1
    exit 0
fi
rm -rf "$DEST"
mkdir -p "$DEST"
tar -C "$DEST" --strip-components=1 -xf "$SRC"
cd "$DEST"
export CC=clang
echo "=== configure $VERSION app-runtime $(date -u) ==="
./configure \
    --enable-fpm \
    --enable-gd \
    --with-freetype \
    --with-jpeg \
    --with-webp \
    --disable-phpdbg \
    --with-openssl \
    --with-libxml \
    --with-sqlite3 \
    --with-pdo-sqlite \
    --with-curl \
    --with-zlib \
    --enable-mbstring \
    --enable-dom \
    --enable-xml \
    --enable-simplexml \
    --enable-xmlwriter \
    --enable-xmlreader \
    --enable-session \
    --enable-filter \
    --enable-ctype \
    --enable-tokenizer \
    --enable-fileinfo \
    --enable-posix \
    --enable-ftp \
    --enable-sockets
echo "=== make $VERSION app-runtime $(date -u) ==="
make -j"$(nproc)"
echo "=== built $VERSION app-runtime $(date -u) ==="
"$CLIBIN" -v | head -1
"$FPMBIN" -v | head -1
