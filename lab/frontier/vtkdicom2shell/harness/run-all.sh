#!/bin/sh
# Replay CVE-2026-22879 pinned-function evidence. All local, no network.
set -u
cd "$(dirname "$0")" || exit 2
pass=0
fail=0
check() {
  if [ "$1" = 0 ]; then pass=$((pass+1)); echo "PASS $2";
  else fail=$((fail+1)); echo "FAIL $2"; fi
}
grep -q 'CHOSEN' /dev/null 2>/dev/null
build() { # name, pin, extra flags
  c++ -std=c++11 -g -O1 $3 -fno-omit-frame-pointer -I. "-DPINNED=\"$2\"" \
    -x c++ main.cxx -o "$1" 2>"$1.build.log"
}
for cc in g++ clang++; do
  command -v "$cc" >/dev/null 2>&1 || continue
  tag=$(basename "$cc")
  echo "== compiler $cc =="
  build "$tag-vuln-asan" pinned-vuln.inc -fsanitize=address
  [ -x "$tag-vuln-asan" ]; check $? "$tag build vuln-asan"
  build "$tag-vuln-plain" pinned-vuln.inc ""
  [ -x "$tag-vuln-plain" ]; check $? "$tag build vuln-plain"
  build "$tag-fixed-asan" pinned-fixed.inc "-fsanitize=address -DFIXED"
  [ -x "$tag-fixed-asan" ]; check $? "$tag build fixed-asan"

  ./$tag-vuln-asan >"$tag-vuln-asan.out" 2>&1
  grep -q 'AddressSanitizer: heap-buffer-overflow' "$tag-vuln-asan.out" &&
    grep -q 'WRITE of size 4' "$tag-vuln-asan.out" &&
    grep -q 'pinned-vuln.inc:127' "$tag-vuln-asan.out"
  check $? "$tag ASan WRITE at pinned e->Tag = tag"

  ./$tag-vuln-plain >"$tag-vuln-plain.out" 2>&1
  grep -q 'count_before=5 cap=4' "$tag-vuln-plain.out" &&
    grep -q 'CHOSEN guard1 word\[4\]=4841434b' "$tag-vuln-plain.out" &&
    grep -q 'CHOSEN guard1 word\[6\]=42424242' "$tag-vuln-plain.out"
  check $? "$tag chosen tag/value at groomed heap offset"

  ./$tag-fixed-asan >"$tag-fixed-asan.out" 2>&1
  r=$?
  grep -q 'AddressSanitizer' "$tag-fixed-asan.out" && r=1
  grep -q 'CHOSEN' "$tag-fixed-asan.out" && r=1
  check $r "$tag fixed control clean"

  ./$tag-fixed-asan safe >"$tag-fixed-asan-safe.out" 2>&1
  r=$?
  grep -q 'AddressSanitizer' "$tag-fixed-asan-safe.out" && r=1
  check $r "$tag fixed safe control clean"
done
echo "TOTAL $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
