#!/usr/bin/env bash
# Additive allocator-size probe: compile against the existing plain libspeex
# builds, assert the corrupted chunk size survives free() into a reused 0x30
# chunk whose 32-byte user area overlaps the next chunk's header. Not part of
# the pinned run-all.sh / witness check set.
set -u
cd "$(dirname "$0")/.."
gcc -O0 -g -I src-plain-vuln/include -I src-plain-vuln \
    harness/alloc-primitive.c src-plain-vuln/libspeex/.libs/libspeex.a -lm \
    -o evidence/alloc-vuln-plain 2>evidence/compile-alloc-vuln.log || exit 2
gcc -O0 -g -I src-plain-fixed/include -I src-plain-fixed \
    harness/alloc-primitive.c src-plain-fixed/libspeex/.libs/libspeex.a -lm \
    -o evidence/alloc-fixed-plain 2>evidence/compile-alloc-fixed.log || exit 2

./evidence/alloc-vuln-plain attack >evidence/alloc-vuln-plain.out 2>&1
vrc=$?
./evidence/alloc-fixed-plain fixed >evidence/alloc-fixed-plain.out 2>&1
frc=$?

fail=0
check() { if grep -q -- "$2" "$1"; then echo "PASS $3"; else echo "FAIL $3"; fail=$((fail+1)); fi; }
[ "$vrc" -eq 0 ] && echo "PASS vulnerable rc=0" || { echo "FAIL vulnerable rc=$vrc"; fail=$((fail+1)); }
[ "$frc" -eq 0 ] && echo "PASS fixed rc=0" || { echo "FAIL fixed rc=$frc"; fail=$((fail+1)); }
check evidence/alloc-vuln-plain.out 'delta=32' 'adjacent malloc(16)'
check evidence/alloc-vuln-plain.out 'bsize_after=0x31' 'forged neighbour chunk size'
check evidence/alloc-vuln-plain.out 'reuse=1' 'malloc(32) returns corrupted chunk'
check evidence/alloc-vuln-plain.out 'overlap=1' 'reused chunk overlaps next header'
check evidence/alloc-fixed-plain.out 'bsize_after=0x21' 'fixed size intact'
check evidence/alloc-fixed-plain.out 'reuse=0' 'fixed malloc does not return neighbour'
check evidence/alloc-fixed-plain.out 'overlap=0' 'fixed no overlap'
echo "TOTAL fail=$fail"
exit "$fail"
