#!/usr/bin/env bash
# Build a NON-sanitized apache2handler module for the Stage A occupant fieldprobe.
# ASan quarantines the freed tzcache chunk, so only a plain build can show which
# object reuses it.  Debug symbols are kept so GDB can break at php_date.c:505.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
V=${1:-8.4.27}
SRC="$ROOT/lab/build/php-$V-plain"
OUT="$ROOT/lab/build/php-$V-apache-plain"
test -d "$SRC" || { echo "run lab/php2shell/build.sh $V plain first" >&2; exit 2; }
rm -rf "$OUT"
cp -a "$SRC" "$OUT"
cd "$OUT"
make clean >/dev/null 2>&1 || true
./buildconf --force >/dev/null
CC=gcc CFLAGS="-g -O0 -fno-omit-frame-pointer" \
  ./configure --disable-all --enable-session --with-apxs2=/usr/bin/apxs2 \
  --disable-phpdbg >/dev/null
make -j2 >/dev/null
test -f "$OUT/.libs/libphp.so"
echo "built $OUT/.libs/libphp.so"
