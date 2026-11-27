#!/bin/sh
# Local only: build vuln/fixed x ASan/plain from pinned sources and assert
# the source-bound stack overflow, chosen bytes past long_name[350], and the
# bounded fixed control. Inputs longer than common NAME_MAX are deliberate:
# the advisory requires a filesystem that permits long filenames.
set -u
cd "$(dirname "$0")"
mkdir -p runs evidence
if ! python3 gen_driver.py; then echo "PIN_DRIFT: abort"; exit 2; fi

CC=${CC:-gcc}
BASE="-std=c11 -O0 -g -fno-omit-frame-pointer -fno-stack-protector"
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

for variant in vuln fixed; do
  for mode in asan plain; do
    flags="$BASE"
    [ "$mode" = asan ] && flags="$flags -fsanitize=address"
    $CC $flags "harness/driver-$variant.c" -o "runs/$variant-$mode" \
      >"evidence/build-$variant-$mode.log" 2>&1 \
      && ok "BUILD_${variant}_${mode}" || bad "BUILD_${variant}_${mode}" "compiler"
  done
done

set +e
ASAN_OPTIONS=detect_leaks=0 ./runs/vuln-asan 4096 >evidence/vuln-asan-4096.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ] && grep -q 'stack-buffer-overflow' evidence/vuln-asan-4096.out \
   && grep -q 'sftpserver.c:1852' evidence/vuln-asan-4096.out; then
  ok ASAN_VULN_WRITE_4096
else
  bad ASAN_VULN_WRITE_4096 "rc=$rc"
fi

set +e
ASAN_OPTIONS=detect_leaks=0 ./runs/vuln-asan 255 >evidence/vuln-asan-255.out 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ] && grep -q 'SETTLED len=255' evidence/vuln-asan-255.out; then
  ok ASAN_VULN_SAFE_255
else
  bad ASAN_VULN_SAFE_255 "rc=$rc"
fi

set +e
ASAN_OPTIONS=detect_leaks=0 ./runs/vuln-asan 292 >evidence/vuln-asan-292.out 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ] && grep -q 'SETTLED len=292 rc=0 longlen=349' evidence/vuln-asan-292.out; then
  ok ASAN_VULN_SAFE_292
else
  bad ASAN_VULN_SAFE_292 "rc=$rc"
fi

set +e
ASAN_OPTIONS=detect_leaks=0 ./runs/vuln-asan 293 >evidence/vuln-asan-293.out 2>&1
rc=$?
set -e
if [ "$rc" -ne 0 ] && grep -q 'stack-buffer-overflow' evidence/vuln-asan-293.out \
   && grep -q 'WRITE of size 316' evidence/vuln-asan-293.out \
   && grep -q 'sftpserver.c:1852' evidence/vuln-asan-293.out; then
  ok ASAN_VULN_WRITE_293
else
  bad ASAN_VULN_WRITE_293 "rc=$rc"
fi

for n in 255 4096; do
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

# The direct driver's 34 chosen bytes plus NUL reach past the array but not
# its saved control data: plain 4096 survives with longlen=384. Keep that
# observed geometry negative; do not relabel it as a plain crash.
set +e
./runs/vuln-plain 4096 >evidence/vuln-plain-4096.out 2>&1
rc=$?
set -e
if [ "$rc" -eq 0 ] && grep -q 'SETTLED len=4096 rc=0 longlen=384' evidence/vuln-plain-4096.out; then
  ok PLAIN_VULN_SURVIVES_4096
else
  bad PLAIN_VULN_SURVIVES_4096 "rc=$rc"
fi

for spec in "vuln-plain 255" "fixed-plain 255" "fixed-plain 4096"; do
  set -- $spec
  set +e
  ./runs/"$1" "$2" >"evidence/$1-$2.out" 2>&1
  rc=$?
  set -e
  [ "$rc" -eq 0 ] && ok "PLAIN_CLEAN_${1}_$2" || bad "PLAIN_CLEAN_${1}_$2" "rc=$rc"
done

if command -v gdb >/dev/null 2>&1 && [ -f harness/readback.gdb ]; then
  gdb -q -batch -x harness/readback.gdb ./runs/vuln-plain \
    >evidence/gdb-readback.out 2>&1
  if grep -q 'CHOSEN_41 41414141414141414141414141414141' evidence/gdb-readback.out \
     && grep -q 'CHOSEN_42 42424242424242424242424242424242' evidence/gdb-readback.out; then
    ok GDB_CHOSEN_BYTES
  else
    bad GDB_CHOSEN_BYTES "readback mismatch"
  fi
else
  printf 'SKIP GDB_CHOSEN_BYTES\n'
fi

{
  printf 'libssh-sftp-longname2shell run-all\n'
  printf 'PASS=%s FAIL=%s\n' "$PASS" "$FAIL"
  for f in evidence/*.out; do
    { printf '%s ' "$f"
      awk '/ERROR: AddressSanitizer/{print "ASAN", $3}
           /WRITE of size/{print "WRITE", $4}
           /SETTLED/{print "SETTLED", $2, $3, $4, $5}
           /CHOSEN_/{print "CHOSEN", $2}
           /Program received/{print "SIGNAL", $4}' "$f"
    } | sha256sum | awk -v n="$f" '{print $1, n}'
  done
} | tee runs/summary.txt

[ "$FAIL" -eq 0 ] || exit 1
printf 'RUN_ALL_OK %s PASS / %s FAIL\n' "$PASS" "$FAIL"
