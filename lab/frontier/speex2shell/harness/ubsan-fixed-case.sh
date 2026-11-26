#!/usr/bin/env bash
# Reproduce the issue #42 already-full-buffer UBSan claim against the PINNED
# vendor fix commit. The pinned bits-fix-09b569d1.c is compiled with UBSan so
# the left shift inside the library is instrumented, then linked ahead of the
# pinned ASan-built fixed libspeex archive. Separate bug, not the OOB claim;
# not part of run-all.sh / the W245 witness set.
set -u
cd "$(dirname "$0")/.."

clang -O0 -g -fsanitize=undefined -DHAVE_CONFIG_H \
    -I src-fixed -I src-fixed/include -I src-fixed/libspeex \
    -c pinned/bits-fix-09b569d1.c -o evidence/ubsan-bits-fixed.o \
    2>evidence/compile-ubsan-bits.log || exit 2
clang -O0 -g -fsanitize=undefined -I src-fixed/include -I src-fixed \
    harness/ubsan-fixed-case.c evidence/ubsan-bits-fixed.o \
    src-fixed/libspeex/.libs/libspeex.a -lm -o evidence/ubsan-fixed-case \
    2>evidence/compile-ubsan-case.log || exit 2

UBSAN_OPTIONS=print_stacktrace=1 ./evidence/ubsan-fixed-case \
    >evidence/ubsan-fixed-case.out 2>&1
rc=$?

fail=0
check() { if grep -q -- "$2" "$1"; then echo "PASS $3"; else echo "FAIL $3"; fail=$((fail+1)); fi; }
[ "$rc" -eq 0 ] && echo "PASS repro rc=0" || { echo "FAIL repro rc=$rc"; fail=$((fail+1)); }
check evidence/ubsan-fixed-case.out 'UndefinedBehaviorSanitizer' 'UBSan report present'
check evidence/ubsan-fixed-case.out 'left shift of negative value -1' 'negative-shift UB'
check evidence/ubsan-fixed-case.out 'bits-fix-09b569d1.c:185:24' 'pinned fixed source line'
check evidence/ubsan-fixed-case.out 'nbytes=8' 'reported truncated nbytes'
echo "TOTAL fail=$fail"
exit "$fail"
