#!/usr/bin/env bash
# Replay runner for the DCMTK CVE-2026-133168 frontier find.
# Usage: bash run.sh <outdir>
set -uo pipefail
cd "$(dirname "$0")"
OUT="${1:-out}"
mkdir -p "$OUT"

python3 gen_driver.py > "$OUT/gen.log" || { cat "$OUT/gen.log"; exit 1; }
CXX="${CXX:-g++}"
$CXX -O0 -g -std=c++17 -o "$OUT/vuln"     driver_vuln.cpp  || exit 1
$CXX -O0 -g -std=c++17 -o "$OUT/fixed"    driver_fixed.cpp || exit 1
$CXX -O0 -g -std=c++17 -fsanitize=address -fno-omit-frame-pointer -DNO_ARENA \
    -o "$OUT/asan" driver_asan.cpp || exit 1

PASS=0
FAIL=0
pass() { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }

# Instrumented chosen-byte readback (rung 1 and rung 4).
o=$("$OUT/vuln" rung1 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$o" | grep -q 'dest=px8+119697 src=in+39899 byte=0x5a' \
   && printf '%s\n' "$o" | grep -q 'dest=px8+119698 src=in+59899 byte=0xa5'; then
  pass 'rung1 chosen bytes read back past px8'
else fail 'rung1 chosen bytes read back past px8'; fi

o=$("$OUT/vuln" rung2 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$o" | grep -q 'alloc=80000 first_oob=80000 max_write=119699 overshoot=39700'; then
  pass 'rung2 accounting failure past 80000-byte declared allocation'
else fail 'rung2 accounting failure past 80000-byte declared allocation'; fi

o=$("$OUT/vuln" rung4 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$o" | grep -q 'rung4 chosen dest=px8+119697=0x5a dest=px8+119698=0xa5' \
   && printf '%s\n' "$o" | grep -q 'rung4 benign dest=px8+119697=0x00 dest=px8+119698=0x00'; then
  pass 'rung4 chosen-value control and benign zero control'
else fail 'rung4 chosen-value control and benign zero control'; fi

set +e
( "$OUT/vuln" guard > "$OUT/guard.out" 2>&1 ) 2>/dev/null
grc=$?
set -e
if [ "$grc" -eq 139 ]; then
  pass 'guard page faults at first past-end write'
else fail "guard page fault (rc=$grc)"; fi

# ASan-confirmed corruption (rung 3).
set +e
"$OUT/asan" asan_rung3 > "$OUT/asan.raw" 2>&1
arc=$?
set -e
python3 normalize.py < "$OUT/asan.raw" > "$OUT/asan.norm"
if [ "$arc" -ne 0 ] && grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$OUT/asan.norm" \
   && grep -q 'WRITE of size 1' "$OUT/asan.norm" \
   && grep -q 'located 0 bytes after 80000-byte region' "$OUT/asan.norm" \
   && grep -q 'frame togglePlanarConfiguration8 djcodece_v3.7.1.cc:1525' "$OUT/asan.norm"; then
  pass 'rung3 ASan WRITE of size 1 after 80000-byte region'
else fail 'rung3 ASan WRITE of size 1 after 80000-byte region'; fi

# Fixed controls: correct stride, and explicit numValues guard rejects short input.
o=$("$OUT/fixed" fixed 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$o" | grep -q 'first_oob=1048576'; then
  pass 'fixed stride leaves past-end region untouched'
else fail 'fixed stride leaves past-end region untouched'; fi

o=$("$OUT/fixed" fixed_reject 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$o" | grep -q 'fixed_reject rc=1 first_write=1048576'; then
  pass 'fixed numValues guard rejects short input with zero writes'
else fail 'fixed numValues guard rejects short input with zero writes'; fi

# Boundary: rows == columns makes the buggy stride equal the correct stride.
o=$("$OUT/vuln" square 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$o" | grep -q 'square alloc=30000 first_oob=1048576'; then
  pass 'square image is clean: overflow is rows>columns specific'
else fail 'square image is clean: overflow is rows>columns specific'; fi

trace() {
  "$OUT/vuln" rung1
  "$OUT/vuln" rung2
  "$OUT/vuln" rung4
  "$OUT/vuln" square
  set +e
  ( "$OUT/vuln" guard >/dev/null 2>&1 ) 2>/dev/null
  printf 'guard rc=%s\n' "$?"
  "$OUT/asan" asan_rung3 2>&1 | python3 normalize.py
  set -e
  "$OUT/fixed" fixed
  "$OUT/fixed" fixed_reject
}
: > "$OUT/trace"
for i in 1 2 3 4 5; do trace >> "$OUT/trace"; done
DIGEST=$(sha256sum "$OUT/trace" | cut -d' ' -f1)
printf 'trace sha256=%s\n' "$DIGEST"

printf '%d PASS / %d FAIL\n' "$PASS" "$FAIL"
if [ "$FAIL" -eq 0 ]; then
  printf 'ALL CHECKS PASS rc 0\n'
  exit 0
fi
exit 1
