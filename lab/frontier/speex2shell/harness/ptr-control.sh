#!/usr/bin/env bash
# Pointer-control probe: compile against the existing plain libspeex builds
# and assert chosen-pointer overwrite plus benign in-process marker execution.
# Not part of the pinned run-all.sh / witness check set.
set -u
cd "$(dirname "$0")/.."
gcc -O0 -g -I src-plain-vuln/include -I src-plain-vuln \
    harness/ptr-control.c src-plain-vuln/libspeex/.libs/libspeex.a -lm \
    -o evidence/ptr-vuln-plain 2>evidence/compile-ptr-vuln.log || exit 2
gcc -O0 -g -I src-plain-fixed/include -I src-plain-fixed \
    harness/ptr-control.c src-plain-fixed/libspeex/.libs/libspeex.a -lm \
    -o evidence/ptr-fixed-plain 2>evidence/compile-ptr-fixed.log || exit 2

./evidence/ptr-vuln-plain attack >evidence/ptr-vuln-plain.out 2>&1
vrc=$?
./evidence/ptr-fixed-plain fixed >evidence/ptr-fixed-plain.out 2>&1
frc=$?

fail=0
check() { if grep -q -- "$2" "$1"; then echo "PASS $3"; else echo "FAIL $3"; fail=$((fail+1)); fi; }
[ "$vrc" -eq 0 ] && echo "PASS vulnerable rc=0" || { echo "FAIL vulnerable rc=$vrc"; fail=$((fail+1)); }
[ "$frc" -eq 0 ] && echo "PASS fixed rc=0" || { echo "FAIL fixed rc=$frc"; fail=$((fail+1)); }
check evidence/ptr-vuln-plain.out 'delta=32' 'adjacent malloc(16)'
check evidence/ptr-vuln-plain.out 'BENIGN_MARKER_CALLED' 'marker through overwritten pointer'
check evidence/ptr-vuln-plain.out 'marker_called=1' 'vulnerable marker'
check evidence/ptr-vuln-plain.out 'tag=5a5a5a5a5a5a5a5a' 'neighbour tag intact'
check evidence/ptr-fixed-plain.out 'marker_called=0' 'fixed control marker absent'

# The pointer bytes in the vulnerable run must equal the printed target.
target=$(grep '^target=' evidence/ptr-vuln-plain.out | cut -d' ' -f1 | cut -d= -f2)
vfn=$(grep '^vfn=' evidence/ptr-vuln-plain.out | cut -d' ' -f1 | cut -d= -f2)
if [ "$target" = "$vfn" ]; then echo "PASS vfn equals chosen target"; else echo "FAIL vfn=$vfn target=$target"; fail=$((fail+1)); fi

echo "TOTAL fail=$fail"
exit "$fail"
