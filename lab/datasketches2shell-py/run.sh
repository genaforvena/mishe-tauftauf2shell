#!/usr/bin/env bash
# Replay the CPython-consumer claims. Exits 0 only when every check passes.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
WORK="$HERE/work"
export PYTHONPATH="$WORK/build52:$WORK/build53:$WORK/buildasan:$WORK/pydeps${PYTHONPATH:+:$PYTHONPATH}"

pass=0
fail=0
check() {
  local name=$1 ok=$2 detail=$3
  if [ "$ok" = 1 ]; then echo "PASS $name: $detail"; pass=$((pass + 1));
  else echo "FAIL $name: $detail"; fail=$((fail + 1)); fi
}

if [ ! -f "$WORK/seed.bin" ]; then bash "$HERE/build.sh" > "$OUT/build.log" 2>&1 || { cat "$OUT/build.log"; exit 2; }; fi

for c in 2 8; do
  log="$OUT/py_${c}.log"
  python3 "$HERE/probe.py" _ds2hll "$c" 0x5a "$WORK/seed.bin" > "$log" 2>&1
  rc=$?
  ok=0; grep -q 'PY_ESTIMATE' "$log" && [ "$rc" -eq 0 ] && ok=1
  check "py_benign_$c" "$ok" "rc=$rc $(tr '\n' ' ' < "$log" | cut -c1-90)"
done

for c in 18 64 255; do
  log="$OUT/py_${c}.log"
  python3 "$HERE/probe.py" _ds2hll "$c" 0x5a "$WORK/seed.bin" > "$log" 2>&1
  rc=$?
  ok=0; [ "$rc" -ne 0 ] && grep -q 'PY_ESTIMATE' "$log" && ok=1
  check "py_hostile_$c" "$ok" "rc=$rc $(tr '\n' ' ' < "$log" | cut -c1-90)"
done

python3 "$HERE/probe.py" _ds2hll53 2 0x5a "$WORK/seed.bin" > "$OUT/py53_benign.log" 2>&1
rc=$?; ok=0; [ "$rc" -eq 0 ] && grep -q 'PY_ESTIMATE' "$OUT/py53_benign.log" && ok=1
check "fixed_benign" "$ok" "rc=$rc $(tr '\n' ' ' < "$OUT/py53_benign.log" | cut -c1-90)"

python3 "$HERE/probe.py" _ds2hll53 64 0x5a "$WORK/seed.bin" > "$OUT/py53_hostile.log" 2>&1
rc=$?; ok=0; [ "$rc" -ne 0 ] && grep -q 'ValueError' "$OUT/py53_hostile.log" && ok=1
check "fixed_rejects_c64" "$ok" "rc=$rc $(tr '\n' ' ' < "$OUT/py53_hostile.log" | cut -c1-120)"

ASAN=$(gcc -print-file-name=libasan.so)
LD_PRELOAD="$ASAN" ASAN_OPTIONS=detect_leaks=0 \
  python3 "$HERE/probe.py" _ds2hllasan 18 0x5a "$WORK/seed.bin" > "$OUT/asan18.log" 2>&1
rc=$?; ok=0
grep -q 'WRITE of size 72' "$OUT/asan18.log" && grep -q '0 bytes after 32-byte region' "$OUT/asan18.log" && \
  grep -q 'hll_wrapper.cpp:100' "$OUT/asan18.log" && [ "$rc" -ne 0 ] && ok=1
check "asan_write" "$ok" "rc=$rc $(grep -m1 'WRITE of size' "$OUT/asan18.log")"

gdb -q -batch -x "$HERE/gdbpy.gdb" --args /usr/bin/python3 "$HERE/probe.py" \
  _ds2hll 18 0x5a "$WORK/seed.bin" > "$OUT/gdb18.log" 2>&1
rc=$?; ok=0
grep -q 'HIT couponCount=18' "$OUT/gdb18.log" && grep -q 'AFTER' "$OUT/gdb18.log" && \
  grep -q '0x5a5a5a5a5a5a5a5a' "$OUT/gdb18.log" && \
  grep -q 'munmap_chunk(): invalid pointer' "$OUT/gdb18.log" && ok=1
check "gdb_write_and_abort" "$ok" "rc=$rc $(grep -m1 'HIT couponCount' "$OUT/gdb18.log")"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
