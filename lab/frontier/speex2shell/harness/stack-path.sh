#!/usr/bin/env bash
# Stack-path probe for CVE-2026-116741: (1) ASan stack-buffer-overflow on a
# stack-backed non-owner SpeexBits; (2) chosen bytes in an adjacent stack
# canary with the plain allocator. Reuses the pinned ASan/plain libspeex
# trees; not part of run-all.sh / the W245 witness check set.
set -u
cd "$(dirname "$0")/.."

# (1) ASan (clang-built pinned trees src-vuln / src-fixed).
clang -O0 -g -fno-omit-frame-pointer -fsanitize=address \
    -I src-vuln/include -I src-vuln harness/stack-asan.c \
    src-vuln/libspeex/.libs/libspeex.a -lm \
    -o evidence/stack-asan-vuln 2>evidence/compile-stack-asan-vuln.log || exit 2
clang -O0 -g -fno-omit-frame-pointer -fsanitize=address \
    -I src-fixed/include -I src-fixed harness/stack-asan.c \
    src-fixed/libspeex/.libs/libspeex.a -lm \
    -o evidence/stack-asan-fixed 2>evidence/compile-stack-asan-fixed.log || exit 2

ASAN_OPTIONS=detect_leaks=0 ./evidence/stack-asan-vuln attack >evidence/stack-asan-vuln.out 2>&1
vrc=$?
ASAN_OPTIONS=detect_leaks=0 ./evidence/stack-asan-fixed fixed >evidence/stack-asan-fixed.out 2>&1
frc=$?

# (2) Plain gcc stack canary.
gcc -O0 -g -I src-plain-vuln/include -I src-plain-vuln harness/stack-canary.c \
    src-plain-vuln/libspeex/.libs/libspeex.a -lm \
    -o evidence/stack-canary-vuln 2>evidence/compile-stack-canary-vuln.log || exit 2
gcc -O0 -g -I src-plain-fixed/include -I src-plain-fixed harness/stack-canary.c \
    src-plain-fixed/libspeex/.libs/libspeex.a -lm \
    -o evidence/stack-canary-fixed 2>evidence/compile-stack-canary-fixed.log || exit 2

./evidence/stack-canary-vuln attack >evidence/stack-canary-vuln.out 2>&1; cvrc=$?
./evidence/stack-canary-fixed fixed >evidence/stack-canary-fixed.out 2>&1; cfrc=$?

fail=0
check() { if grep -q -- "$2" "$1"; then echo "PASS $3"; else echo "FAIL $3"; fail=$((fail+1)); fi; }
[ "$vrc" -ne 0 ] && echo "PASS ASan vulnerable detected rc=$vrc" || { echo "FAIL ASan vulnerable rc=$vrc"; fail=$((fail+1)); }
check evidence/stack-asan-vuln.out 'stack-buffer-overflow' 'ASan stack-buffer-overflow'
check evidence/stack-asan-vuln.out 'WRITE of size 1' 'ASan WRITE of size 1'
check evidence/stack-asan-vuln.out 'bits.c:184' 'sink at verbatim bits.c:184'
[ "$frc" -eq 0 ] && echo "PASS ASan fixed rc=0" || { echo "FAIL ASan fixed rc=$frc"; fail=$((fail+1)); }
check evidence/stack-asan-fixed.out 'nbytes=15' 'fixed attack clean'
check evidence/stack-canary-vuln.out 'delta=16' 'canary adjacent to stack buffer'
check evidence/stack-canary-vuln.out '696a6b6c6d6e6f70' 'chosen bytes in stack canary'
check evidence/stack-canary-vuln.out 'changed=16 chosen=8' 'vulnerable stack canary corrupted'
check evidence/stack-canary-fixed.out 'changed=0 chosen=0' 'fixed stack canary intact'
[ "$cvrc" -eq 0 ] && echo "PASS canary vulnerable rc=0" || { echo "FAIL canary vuln rc=$cvrc"; fail=$((fail+1)); }
[ "$cfrc" -eq 0 ] && echo "PASS canary fixed rc=0" || { echo "FAIL canary fixed rc=$cfrc"; fail=$((fail+1)); }
echo "TOTAL fail=$fail"
exit "$fail"
