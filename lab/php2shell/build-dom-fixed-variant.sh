#!/bin/bash
# php2shell — make the patch-sensitive "fixed" 129501 binary from the
# dom-enabled 8.5.12-asan build produced by build-dom.sh.
#
# Usage: bash lab/php2shell/build-dom-fixed-variant.sh
#
# Saves the affected CLI as sapi/cli/php-vuln, replaces ext/dom/xml_serializer.c
# with the byte-identical 8.5.13 file, rebuilds only that TU and relinks, and
# saves the result as sapi/cli/php-fixed. This is a real-fix patch-sensitivity
# comparison, NOT a full 8.5.13 build. Run build-dom.sh 8.5.12 first.

set -e
SITE=$(cd "$(dirname "$0")/../.." && pwd)
BUILD="$SITE/lab/build"
DEST="$BUILD/php-8.5.12-asan-dom"
FIXSRC="$BUILD/php-8.5.13/ext/dom/xml_serializer.c"

[ -x "$DEST/sapi/cli/php" ] || { echo "missing $DEST/sapi/cli/php — run build-dom.sh 8.5.12 first"; exit 1; }
[ -f "$FIXSRC" ] || { echo "missing $FIXSRC — run provision.sh first"; exit 1; }

cp "$DEST/sapi/cli/php" "$DEST/sapi/cli/php-vuln"
cp "$FIXSRC" "$DEST/ext/dom/xml_serializer.c"
diff -q "$FIXSRC" "$DEST/ext/dom/xml_serializer.c"
cd "$DEST"
make -j"$(nproc)"
cp sapi/cli/php sapi/cli/php-fixed

echo "vulnerable: $DEST/sapi/cli/php-vuln"
echo "fixed:      $DEST/sapi/cli/php-fixed"
echo "replay: python3 lab/repro/php2shell-cve129501-dom.py <vulnerable> <fixed>"
