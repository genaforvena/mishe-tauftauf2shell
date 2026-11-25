#!/bin/bash
# One-command replay for Aspell CVE-2026-75818 (prezip ADV macro).
# Pinned full vulnerable/fixed prezip.c, crafted prezip stream, GCC+Clang ASan,
# fixed and safe-input controls. No bytes chosen at a chosen destination.
set -u
cd "$(dirname "$0")"
mkdir -p evidence
pass=0; fail=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
no() { fail=$((fail+1)); echo "FAIL $1"; }

if (cd ../pins && sha256sum -c SHA256SUMS >/dev/null 2>&1); then ok "pin sha256 4/4"; else no "pin sha256 4/4"; fi
if diff -u ../pins/prezip.vuln.c ../pins/prezip.fixed.c | grep -q 'if (\*w == 0) {ret = 3; goto error;}'; then ok "fix hunk present"; else no "fix hunk present"; fi

for cc in gcc clang; do
  $cc -std=gnu99 -O0 -g -fno-omit-frame-pointer -fsanitize=address ../pins/prezip.vuln.c -o vuln-$cc-asan 2>evidence/$cc-vuln-build.log && ok "$cc vuln asan build" || no "$cc vuln asan build"
  $cc -std=gnu99 -O0 -g -fno-omit-frame-pointer -fsanitize=address ../pins/prezip.fixed.c -o fixed-$cc-asan 2>evidence/$cc-fixed-build.log && ok "$cc fixed asan build" || no "$cc fixed asan build"
done
gcc -std=gnu99 -O0 -g ../pins/prezip.vuln.c -o vuln-plain 2>evidence/gcc-plain-build.log && ok "gcc vuln plain build" || no "gcc vuln plain build"

bash write-inputs.sh >/dev/null 2>&1
[ -s evidence/crafted.bin ] && ok "crafted stream present" || no "crafted stream present"

for cc in gcc clang; do
  out="evidence/vuln-$cc-asan.out"
  ./vuln-$cc-asan -d <evidence/crafted.bin >"$out.stdout" 2>"$out"; rc=$?
  if [ "$rc" -ne 0 ] && grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$out" && grep -q 'READ of size 1' "$out" && grep -q 'prezip.vuln.c:173' "$out"; then ok "vuln-$cc-asan crafted heap OOB READ at pinned :173"; else no "vuln-$cc-asan crafted heap OOB READ at pinned :173 (rc=$rc)"; fi
  out="evidence/fixed-$cc-asan.out"
  ./fixed-$cc-asan -d <evidence/crafted.bin >"$out.stdout" 2>"$out"; rc=$?
  if [ "$rc" -eq 3 ] && grep -q 'corrupt input' "$out" && ! grep -q 'AddressSanitizer' "$out"; then ok "fixed-$cc-asan crafted rejected clean"; else no "fixed-$cc-asan crafted rejected clean (rc=$rc)"; fi
done

./vuln-gcc-asan -d <evidence/crafted-clean.bin >evidence/safe-vuln.stdout 2>evidence/safe-vuln.err; rc=$?
if [ "$rc" -eq 0 ] && grep -q 'HELLO' evidence/safe-vuln.stdout && ! grep -q 'AddressSanitizer' evidence/safe-vuln.err; then ok "vuln safe input clean"; else no "vuln safe input clean (rc=$rc)"; fi
./fixed-gcc-asan -d <evidence/crafted-clean.bin >evidence/safe-fixed.stdout 2>evidence/safe-fixed.err; rc=$?
if [ "$rc" -eq 0 ] && grep -q 'HELLO' evidence/safe-fixed.stdout && ! grep -q 'AddressSanitizer' evidence/safe-fixed.err; then ok "fixed safe input clean"; else no "fixed safe input clean (rc=$rc)"; fi

echo "RESULT $pass PASS / $fail FAIL"
test "$fail" -eq 0
