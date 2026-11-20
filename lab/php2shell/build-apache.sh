#!/usr/bin/env bash
# Build PHP 8.4.26 apache2handler module for the mod_php consumer lane.
# This lane deliberately has NO --enable-debug: ZEND_DEBUG forces
# fast_shutdown=0, but the advisory's confirmed SAPI is release fast-shutdown.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
V=${1:-8.4.26}
SRC="$ROOT/lab/build/php-$V-asan"
OUT="$ROOT/lab/build/php-$V-apache-asan"
test -d "$SRC" || { echo "run lab/php2shell/build.sh $V asan first" >&2; exit 2; }
rm -rf "$OUT"
cp -a "$SRC" "$OUT"
cd "$OUT"
make clean >/dev/null 2>&1 || true
./buildconf --force >/dev/null
CC=clang CFLAGS="-fsanitize=address,undefined -fno-sanitize=function -fno-omit-frame-pointer -O1 -g" \
  ./configure --disable-all --enable-session --with-apxs2=/usr/bin/apxs2 --disable-phpdbg >/dev/null
make -j4 >/dev/null
test -f "$OUT/.libs/libphp.so"
echo "built $OUT/.libs/libphp.so"
