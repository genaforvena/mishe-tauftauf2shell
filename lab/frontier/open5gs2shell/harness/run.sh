#!/bin/sh
# open5gs2shell staged harness (CVE-2026-116543). Evidence in evidence/*.out.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p harness/evidence
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}
CFLAGS="-O0 -g -Iharness -Iprovision"
SRC="harness/harness.c provision/multipart_parser-v2.8.0.c"

cc $CFLAGS -fsanitize=address $SRC -o harness/asan-vuln 2>harness/evidence/build-asan-vuln.log
cc $CFLAGS -fsanitize=address -DFIXED_BUILD $SRC -o harness/asan-fixed 2>harness/evidence/build-asan-fixed.log
cc $CFLAGS $SRC -o harness/plain-vuln 2>harness/evidence/build-plain-vuln.log
cc $CFLAGS -DFIXED_BUILD $SRC -o harness/plain-fixed 2>harness/evidence/build-plain-fixed.log
check 01-four-builds-ok "$?"

ASAN_OPTIONS=detect_leaks=0 harness/asan-vuln attack >harness/evidence/asan-vuln-attack.out 2>&1
RC=$?
check 02-asan-vuln-attack-faults "$([ "$RC" -ne 0 ] && echo 0 || echo 1)"
grep -q 'ERROR: AddressSanitizer' harness/evidence/asan-vuln-attack.out
check 03-asan-report-present "$?"
grep -q 'WRITE of size 1' harness/evidence/asan-vuln-attack.out
check 04-asan-write-1 "$?"
grep -q 'multipart_parser-v2.8.0.c:260' harness/evidence/asan-vuln-attack.out
check 05-asan-write-at-pinned-sink "$?"
grep -q '0 bytes after 65-byte region' harness/evidence/asan-vuln-attack.out
check 06-asan-zero-bytes-past-parser-allocation "$?"
grep -q 'multipart_parser_init provision/multipart_parser-v2.8.0.c:82' harness/evidence/asan-vuln-attack.out
check 07-allocation-is-verbatim-init "$?"

ASAN_OPTIONS=detect_leaks=0 harness/asan-vuln safe >harness/evidence/asan-vuln-safe.out 2>&1
check 08-asan-safe-clean "$?"
ASAN_OPTIONS=detect_leaks=0 harness/asan-fixed attack >harness/evidence/asan-fixed-attack.out 2>&1
check 09-asan-fixed-attack-clean "$?"
grep -q 'RET=-1' harness/evidence/asan-fixed-attack.out
check 10-fixed-rejects-empty-boundary "$?"

harness/plain-vuln safe >harness/evidence/plain-vuln-safe.out 2>&1
check 11-plain-safe-runs "$?"
grep -q 'RET=10 LEN=10' harness/evidence/plain-vuln-safe.out
check 12-plain-safe-consumes-only-framing "$?"
grep -q 'CANARY-AFTER=5a5a5a5a5a5a5a5a5a5a5a5a' harness/evidence/plain-vuln-safe.out
check 13-plain-safe-canary-intact "$?"

harness/plain-fixed attack >harness/evidence/plain-fixed-attack.out 2>&1
check 14-plain-fixed-attack-runs "$?"
grep -q 'ERROR=Empty multipart boundary' harness/evidence/plain-fixed-attack.out
check 15-fixed-hunk-fires-before-init "$?"

harness/plain-vuln attack >harness/evidence/plain-vuln-attack.out 2>&1
check 16-plain-attack-runs "$?"
grep -q 'RET=394 LEN=394' harness/evidence/plain-vuln-attack.out
check 17-full-attacker-body-consumed "$?"
grep -q 'CANARY-BEFORE=5a5a5a5a5a5a5a5a5a5a5a5a' harness/evidence/plain-vuln-attack.out
check 18-plain-attack-canary-pristine-before "$?"
grep -q 'CANARY-AFTER=0a000d0a000d0a000d0a000d' harness/evidence/plain-vuln-attack.out
check 19-chosen-periodic-bytes-in-adjacent-heap "$?"

grep -q 'if (!boundary\[0\]) {' harness/harness.c
grep -q 'ogs_free(boundary);' harness/harness.c
grep -q 'p->lookbehind\[2 + p->index\] = c;' provision/multipart_parser-v2.8.0.c
check 20-verbatim-fix-and-sink-present "$?"

sha256sum -c pins.sha256 >harness/evidence/pins.out 2>&1
check 21-pins-exact "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
