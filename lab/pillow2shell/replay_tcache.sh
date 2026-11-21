#!/bin/sh
# W13 negative lane: a Python-level groom does not put a free chunk in the
# tile buffer's OOB span.  Needs gdb, non-PIE python3.12, plain 12.2.0 build.
set -eu
BUILD=${PILLOW_BUILD:-/tmp/pw2-w9/v12plain}
OUT=$1
mkdir -p "$OUT"
cd "$(dirname "$0")"
PYTHONPATH="$BUILD" gdb -q -batch -x tcache_place.gdb --args \
  python3 groom_tcache.py case_tcache.fpx 128 > "$OUT/place.log" 2>&1
grep -q '^GROOM sz=128 ' "$OUT/place.log"
grep -q '^BUF=' "$OUT/place.log"
grep -q '^NEIGH size=21 ' "$OUT/place.log"
if grep -q '^FOUND_[XY] ' "$OUT/place.log"; then
  echo "FAIL: groomed chunk survived in tcache" >&2
  exit 1
fi
echo "PASS: no groomed free chunk in OOB span; neighbour still live"
