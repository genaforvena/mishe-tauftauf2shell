#!/bin/bash
# One-command replay: provenance, four builds, vulnerable/fixed/safe controls.
set -u
cd "$(dirname "$0")"
mkdir -p evidence
pass=0; fail=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
no() { fail=$((fail+1)); echo "FAIL $1"; }

./extract-pins.sh >evidence/pin-hashes.out 2>&1 || exit 2
if (cd ../pins && sha256sum -c SHA256SUMS >/dev/null 2>&1); then ok "pin sha256 2/2"; else no "pin sha256 2/2"; fi
if diff -q <(sed -n '170,280p' ../pins/m_kill.vuln.c) pinned_vuln.h >/dev/null; then ok "vuln body == pin 170-280"; else no "vuln body == pin 170-280"; fi
if diff -q <(sed -n '170,284p' ../pins/m_kill.fixed.c) pinned_fixed.h >/dev/null; then ok "fixed body == pin 170-284"; else no "fixed body == pin 170-284"; fi
if diff -q <(sed -n '170,197p' ../pins/m_kill.fixed.c) <(sed -n '170,197p' ../pins/m_kill.vuln.c) >/dev/null; then ok "fixed/vuln identical through 197"; else no "fixed/vuln identical through 197"; fi

gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -fsanitize=address probe.c -o vuln-gcc-asan 2>evidence/gcc-vuln-build.log && ok "gcc vuln asan build" || no "gcc vuln asan build"
clang -std=gnu11 -O0 -g -fno-omit-frame-pointer -fsanitize=address probe.c -o vuln-clang-asan 2>evidence/clang-vuln-build.log && ok "clang vuln asan build" || no "clang vuln asan build"
gcc -std=gnu11 -O0 -g -fno-omit-frame-pointer -fsanitize=address -DMISHE_FIXED probe.c -o fixed-gcc-asan 2>evidence/gcc-fixed-build.log && ok "gcc fixed asan build" || no "gcc fixed asan build"
gcc -std=gnu11 -O0 -g -DMISHE_PLAIN probe.c -o vuln-gcc-plain 2>evidence/gcc-plain-build.log && ok "gcc plain build" || no "gcc plain build"

for cc in gcc clang; do
  for n in 510 700; do
    out="evidence/vuln-$cc-asan-$n.out"
    ./vuln-$cc-asan "$n" >"$out" 2>&1; rc=$?
    if [ "$rc" -ne 0 ] && grep -q 'global-buffer-overflow' "$out" && grep -q 'WRITE of size' "$out"; then ok "vuln-$cc-asan reason=$n global WRITE"; else no "vuln-$cc-asan reason=$n global WRITE (rc=$rc)"; fi
  done
  out="evidence/vuln-$cc-asan-safe.out"
  ./vuln-$cc-asan 480 >"$out" 2>&1; rc=$?
  if [ "$rc" -eq 0 ] && grep -q clean "$out"; then ok "vuln-$cc-asan reason=480 clean"; else no "vuln-$cc-asan reason=480 clean (rc=$rc)"; fi
done

for n in 510 700; do
  out="evidence/fixed-gcc-asan-$n.out"
  ./fixed-gcc-asan "$n" >"$out" 2>&1; rc=$?
  if [ "$rc" -eq 0 ] && grep -q clean "$out" && ! grep -q 'AddressSanitizer' "$out"; then ok "fixed reason=$n clean"; else no "fixed reason=$n clean (rc=$rc)"; fi
done

./vuln-gcc-plain 510 >evidence/plain-510.out 2>&1
if grep -q 'buf_len=532' evidence/plain-510.out && grep -q '^oob=.*SOLANUM-OOB-MISHE-' evidence/plain-510.out; then ok "plain chosen bytes past buf+512"; else no "plain chosen bytes past buf+512"; fi
./vuln-gcc-plain 480 >evidence/plain-480.out 2>&1
if grep -q 'buf_len=502' evidence/plain-480.out && ! grep -q 'MISHE' evidence/plain-480.out; then ok "plain safe reason=480 no OOB"; else no "plain safe reason=480 no OOB"; fi
echo "RESULT $pass PASS / $fail FAIL"
test "$fail" -eq 0
