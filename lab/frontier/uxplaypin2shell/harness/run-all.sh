#!/bin/sh
# UxPlay GHSA-479c-ww7g-wgp8 pinned-sink replay. Offline: g++, gdb.
set -u
cd "$(dirname "$0")/.." || exit 1
pass=0; fail=0
note() { printf '%s\n' "$1"; }
check() { # name, condition-result
  if [ "$2" = 1 ]; then note "PASS: $1"; pass=$((pass+1));
  else note "FAIL: $1"; fail=$((fail+1)); fi
}
have() { grep -q "$2" "$1" && echo 1 || echo 0; }
absent() { grep -q "$2" "$1" && echo 0 || echo 1; }

note "== pins =="
sha256sum -c SHA256SUMS || exit 2

note "== build =="
CFLAGS="-g -O0 -D_FORTIFY_SOURCE=0 -fno-stack-protector -fno-omit-frame-pointer"
g++ $CFLAGS -fsanitize=address -o harness/vuln-asan0 harness/uxplaypin.cpp || exit 2
g++ $CFLAGS -fsanitize=address -DFIXED -o harness/fixed-asan0 harness/uxplaypin.cpp || exit 2
g++ $CFLAGS -no-pie -o harness/vuln-plain harness/uxplaypin.cpp || exit 2

note "== vulnerable arm =="
./harness/vuln-asan0 attack > evidence/vuln-asan0-attack.out 2>&1
check "vuln attack ASan stack-buffer-overflow" "$(have evidence/vuln-asan0-attack.out 'ERROR: AddressSanitizer: stack-buffer-overflow')"
check "vuln attack WRITE size 128" "$(have evidence/vuln-asan0-attack.out 'WRITE of size 128')"
check "vuln attack sink frame" "$(have evidence/vuln-asan0-attack.out 'in handler_pin harness/uxplaypin.cpp:38')"
./harness/vuln-asan0 rip > evidence/vuln-asan0-rip.out 2>&1
check "vuln rip WRITE size 80" "$(have evidence/vuln-asan0-rip.out 'WRITE of size 80')"
./harness/vuln-asan0 safe > evidence/vuln-asan0-safe.out 2>&1
check "vuln safe clean" "$(absent evidence/vuln-asan0-safe.out 'ERROR: AddressSanitizer')"
check "vuln safe decoded" "$(have evidence/vuln-asan0-safe.out 'proof_len=20')"

note "== fixed arm =="
for inp in attack rip safe; do
  ./harness/fixed-asan0 "$inp" > "evidence/fixed-asan0-$inp.out" 2>&1
  check "fixed $inp clean" "$(absent "evidence/fixed-asan0-$inp.out" 'ERROR: AddressSanitizer')"
done

note "== saved-RIP control =="
if command -v gdb >/dev/null 2>&1; then
  gdb -q -batch -ex 'set pagination off' -ex 'break uxplaypin.cpp:38' \
      -ex 'run attack' -ex 'next' -ex 'info frame' ./harness/vuln-plain \
      > evidence/gdb-savedrip.out 2>&1
  check "chosen 0x43 at saved RIP" "$(have evidence/gdb-savedrip.out 'saved rip = 0x4343434343434343')"
else
  check "gdb present" 0
fi

sum=$(cat evidence/vuln-asan0-attack.out evidence/vuln-asan0-rip.out \
        evidence/vuln-asan0-safe.out evidence/fixed-asan0-*.out \
        | grep -E 'ERROR: AddressSanitizer|WRITE of size|proof_len=' \
        | sha256sum | cut -d' ' -f1)
note "RUN_ALL_OK $pass PASS / $fail FAIL"
note "SUMMARY_SHA256 $sum"
[ "$fail" -eq 0 ]
