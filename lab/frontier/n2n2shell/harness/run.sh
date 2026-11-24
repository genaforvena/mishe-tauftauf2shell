#!/bin/sh
# n2n2shell staged harness. Evidence in evidence/*.out; pins in PROVENANCE.md.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p harness/evidence
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}

cc -O0 -g -fsanitize=address -DASAN_BUILD -I. harness/harness.c generated/handlers_vuln.c -o harness/asan-vuln 2>harness/evidence/build-asan-vuln.log
cc -O0 -g -fsanitize=address -DASAN_BUILD -I. harness/harness.c generated/handlers_fixed.c -o harness/asan-fixed 2>harness/evidence/build-asan-fixed.log
cc -O0 -g -I. harness/harness.c generated/handlers_vuln.c -o harness/plain-vuln 2>harness/evidence/build-plain-vuln.log
cc -O0 -g -I. harness/harness.c generated/handlers_fixed.c -o harness/plain-fixed 2>harness/evidence/build-plain-fixed.log
check 01-4-builds-ok "$?"

harness/asan-vuln attack >harness/evidence/asan-vuln-attack.out 2>&1
RC=$?
check 02-asan-vuln-attack-faults "$([ "$RC" -ne 0 ] && echo 0 || echo 1)"
grep -q 'ERROR: AddressSanitizer' harness/evidence/asan-vuln-attack.out
check 03-asan-report-present "$?"
grep -q 'WRITE of size' harness/evidence/asan-vuln-attack.out
check 04-asan-write-primitive "$?"
grep -q 'decode_REGISTER_SUPER_NAK' harness/evidence/asan-vuln-attack.out
check 05-asan-frame-verbatim-function "$?"

harness/asan-vuln safe >harness/evidence/asan-vuln-safe.out 2>&1
check 06-asan-vuln-safe-clean "$?"
harness/asan-fixed attack >harness/evidence/asan-fixed-attack.out 2>&1
check 07-asan-fixed-attack-clean "$?"

harness/plain-vuln safe >harness/evidence/plain-vuln-safe.out 2>&1
check 08-plain-vuln-safe-clean "$?"
grep -q 'CANARY=abababab EXPECT=485a4d49' harness/evidence/plain-vuln-safe.out
check 09-plain-safe-canary-intact "$?"
harness/plain-fixed attack >harness/evidence/plain-fixed-attack.out 2>&1
check 10-plain-fixed-attack-clean "$?"
grep -q 'RET=-1' harness/evidence/plain-fixed-attack.out
check 11-fixed-rejects-oversize "$?"
grep -q 'CANARY=abababab EXPECT=485a4d49' harness/evidence/plain-fixed-attack.out
check 12-plain-fixed-canary-intact "$?"

harness/plain-vuln attack >harness/evidence/plain-vuln-attack.out 2>&1
check 13-plain-vuln-attack-runs "$?"
grep -q 'CANARY=485a4d49 EXPECT=485a4d49' harness/evidence/plain-vuln-attack.out
check 14-chosen-bytes-in-adjacent-canary "$?"

sha256sum -c pins.sha256 >harness/evidence/pins.out 2>&1
check 15-pins-exact "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
