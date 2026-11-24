#!/bin/sh
# pgactive2shell staged harness. Evidence in evidence/*.out; pins in pins.sha256.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p harness/evidence
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}

cc -O0 -g -fsanitize=address -Iharness harness/harness.c generated/functions_vuln.c -o harness/asan-vuln 2>harness/evidence/build-asan-vuln.log
cc -O0 -g -fsanitize=address -Iharness harness/harness.c generated/functions_fixed.c -o harness/asan-fixed 2>harness/evidence/build-asan-fixed.log
cc -O0 -g -DCAPTURE_MODE -Iharness harness/harness.c generated/functions_vuln.c -o harness/plain-vuln 2>harness/evidence/build-plain-vuln.log
cc -O0 -g -DCAPTURE_MODE -Iharness harness/harness.c generated/functions_fixed.c -o harness/plain-fixed 2>harness/evidence/build-plain-fixed.log
check 01-four-builds-ok "$?"

harness/asan-vuln attack >harness/evidence/asan-vuln-attack.out 2>&1
RC=$?
check 02-asan-vuln-attack-faults "$([ "$RC" -ne 0 ] && echo 0 || echo 1)"
grep -q 'ERROR: AddressSanitizer' harness/evidence/asan-vuln-attack.out
check 03-asan-report-present "$?"
grep -q 'WRITE of size 97' harness/evidence/asan-vuln-attack.out
check 04-asan-write-97 "$?"
grep -q "offset 96 in frame" harness/evidence/asan-vuln-attack.out
check 05-asan-zero-bytes-past-64-byte-name "$?"
grep -q 'pgactive_parse_replident_name generated/functions_vuln.c' harness/evidence/asan-vuln-attack.out
check 06-asan-frame-verbatim-function "$?"

harness/asan-vuln safe >harness/evidence/asan-vuln-safe.out 2>&1
check 07-asan-vuln-safe-clean "$?"
harness/asan-fixed attack >harness/evidence/asan-fixed-attack.out 2>&1
check 08-asan-fixed-attack-clean "$?"

harness/plain-vuln safe >harness/evidence/plain-vuln-safe.out 2>&1
check 09-plain-vuln-safe-runs "$?"
grep -q 'RET=0' harness/evidence/plain-vuln-safe.out
check 10-plain-safe-accepted "$?"

harness/plain-fixed attack >harness/evidence/plain-fixed-attack.out 2>&1
check 11-plain-fixed-attack-runs "$?"
grep -q 'RET=-1' harness/evidence/plain-fixed-attack.out
check 12-fixed-rejects-oversize-name "$?"
grep -q 'CAPTURE=NONE' harness/evidence/plain-fixed-attack.out
check 13-fixed-has-no-stack-write "$?"

# The plain vulnerable run is expected to abort after the capture (stack
# protector); the in-function capture is the evidence, not its exit code.
harness/plain-vuln attack >harness/evidence/plain-vuln-attack.out 2>&1
grep -q 'CAPTURE-IN=' harness/evidence/plain-vuln-attack.out
check 14-plain-attack-capture-produced "$?"
grep -q 'CAPTURE-IN=485a4d49 EXPECT=485a4d49' harness/evidence/plain-vuln-attack.out
check 15-chosen-bytes-in-buffer "$?"
grep -q 'CAPTURE-CANARY64=485a4d49 EXPECT=485a4d49' harness/evidence/plain-vuln-attack.out
check 16-chosen-bytes-past-64-byte-name "$?"
grep -q 'CAPTURE-MARKTAIL=485a4d49 EXPECT=485a4d49' harness/evidence/plain-vuln-attack.out
check 17-chosen-bytes-at-written-tail "$?"

grep -q 'NameStr(replication_name)) != 4)' generated/functions_vuln.c
grep -q 'riname\[parsed_len\] != .\\0.)' generated/functions_fixed.c
check 18-verbatim-fix-hunks-present "$?"

sha256sum -c pins.sha256 >harness/evidence/pins.out 2>&1
check 19-pins-exact "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
