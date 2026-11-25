#!/bin/bash
# ctranslate22shell staged harness: verbatim pinned loader functions + stand-in consumer.
set -u
cd "$(dirname "$0")"
mkdir -p evidence
fail=0
pass=0
ok() { pass=$((pass+1)); echo "PASS $1"; }
no() { fail=$((fail+1)); echo "FAIL $1"; }
check() { if "$@" >/dev/null 2>&1; then ok "$1"; else no "$1"; fi; }

# Provenance: pinned functions must be byte-identical to the upstream pins.
if diff -q <(sed -n '43,87p' ../pins/model-v4.8.0.cc) <(sed -n '10,54p' pinned_consume.h) >/dev/null 2>&1; then ok "consume snippet == vuln pin 43-87"; else no "consume snippet == vuln pin 43-87"; fi
# The fixed pin also hardens consume<std::string>; the payload path under
# test uses the byte-identical buffer overload only. Check pin hashes instead.
if (cd ../pins && sha256sum -c SHA256SUMS >/dev/null 2>&1); then ok "pin sha256 2/2"; else no "pin sha256 2/2"; fi
if diff -q <(sed -n '639,657p' ../pins/model-v4.8.0.cc) <(sed -n '67,85p' probe_vuln.cpp) >/dev/null 2>&1; then ok "caller snippet == vuln pin 639-657"; else no "caller snippet == vuln pin 639-657"; fi
if diff -q <(sed -n '641,661p' ../pins/model-fixed.cc) <(sed -n '66,86p' probe_fixed.cpp) >/dev/null 2>&1; then ok "caller snippet == fixed pin 641-661"; else no "caller snippet == fixed pin 641-661"; fi

g++ -std=c++17 -O0 -g -DMISHE_ASAN -fno-omit-frame-pointer -fsanitize=address probe_vuln.cpp -o vuln-gcc-asan 2>evidence/gcc-vuln-build.log || exit 2
clang++ -std=c++17 -O0 -g -DMISHE_ASAN -fno-omit-frame-pointer -fsanitize=address probe_vuln.cpp -o vuln-clang-asan 2>evidence/clang-vuln-build.log || exit 2
g++ -std=c++17 -O0 -g -DMISHE_ASAN -fno-omit-frame-pointer -fsanitize=address probe_fixed.cpp -o fixed-gcc-asan 2>evidence/gcc-fixed-build.log || exit 2
g++ -std=c++17 -O0 -g probe_vuln.cpp -o vuln-gcc-plain 2>evidence/gcc-plain-build.log || exit 2
ok "four builds"

for cc in gcc clang; do
  bin="vuln-$cc-asan"
  for n in 17 64; do
    out="evidence/$bin-$n.out"
    ./$bin "$n" >"$out" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ] && grep -q 'heap-buffer-overflow' "$out" && grep -q 'WRITE of size' "$out"; then ok "$bin payload=$n ASan WRITE"; else no "$bin payload=$n ASan WRITE (rc=$rc)"; fi
  done
  ./$bin 16 >"evidence/$bin-safe.out" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] && grep -q clean "evidence/$bin-safe.out"; then ok "$bin safe payload=16 clean"; else no "$bin safe payload=16 clean"; fi
done

for n in 17 64; do
  out="evidence/fixed-gcc-asan-$n.out"
  ./fixed-gcc-asan "$n" >"$out" 2>&1
  rc=$?
  if [ "$rc" -eq 0 ] && grep -q "invalid payload size" "$out" && ! grep -q 'ERROR: AddressSanitizer' "$out"; then ok "fixed rejects payload=$n"; else no "fixed rejects payload=$n"; fi
done
./fixed-gcc-asan 16 >evidence/fixed-gcc-asan-safe.out 2>&1
if [ "$?" -eq 0 ] && grep -q clean evidence/fixed-gcc-asan-safe.out; then ok "fixed safe payload=16 clean"; else no "fixed safe payload=16 clean"; fi

./vuln-gcc-plain 17 >evidence/plain-17.out 2>&1
if grep -q '^marker=I[.]*' evidence/plain-17.out; then ok "plain chosen byte at buffer+16"; else no "plain chosen byte at buffer+16"; fi
./vuln-gcc-plain 48 >evidence/plain-48.out 2>&1
if grep -q '^marker=ITEMISHE-CT2-OOB$' evidence/plain-48.out; then ok "plain chosen bytes across 32-byte follower"; else no "plain chosen bytes across 32-byte follower"; fi

echo "RESULT $pass PASS / $fail FAIL"
test "$fail" -eq 0
