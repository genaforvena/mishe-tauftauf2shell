#!/bin/bash
# php2shell — NON-ASan dom-enabled CLI lab build, for chosen-byte occupant work
# on the DOM reflected-attribute setter UAF (wake 55/56).
#
# Usage: bash lab/php2shell/build-dom-plain.sh VERSION   (VERSION = 8.5.12)
#
# ASan quarantines a free, so the freed 120-B xmlNode chunk is never reused.
# A plain (glibc malloc) build is required to observe what occupant lands at
# the stale wrapper's read offsets. Produces sapi/cli/php with ext/dom +
# ext/libxml + bundled lexbor, no sanitizers. Idempotent. Local only.

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$SITE/lab/build"

VERSION=$1
[ -n "$VERSION" ] || { echo "usage: $0 VERSION(8.5.12)"; exit 1; }

SRCTREE="$BUILD/php-$VERSION"
[ -d "$SRCTREE" ] || { echo "missing $SRCTREE — run lab/php2shell/provision.sh first"; exit 1; }

# Deliberately no -fsanitize. Keep -g -O1 so GDB can inspect the stale wrapper.
export CC=clang
export CFLAGS="-fno-omit-frame-pointer -g -O1"
export LDFLAGS=""

DEST="$BUILD/php-$VERSION-plain-dom"
if [ ! -d "$DEST" ]; then
    echo "copying source tree to $DEST"
    cp -a "$SRCTREE" "$DEST"
fi

BIN_PHP="$DEST/sapi/cli/php"
if [ ! -x "$BIN_PHP" ]; then
    cd "$DEST"
    ./configure \
        --disable-all \
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
