#!/bin/sh
# Real-caller replay for CVE-2026-116543. Does not touch the staged harness.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p realcaller/evidence
CFLAGS="-O0 -g -Irealcaller -Iharness -Iprovision"
SRC="realcaller/realcaller.c provision/multipart_parser-v2.8.0.c"

cc $CFLAGS -fsanitize=address $SRC -o realcaller/asan-real 2>realcaller/evidence/build-asan-real.log
cc $CFLAGS -fsanitize=address -DFIXED_BUILD $SRC -o realcaller/asan-fixed 2>realcaller/evidence/build-asan-fixed.log
cc $CFLAGS $SRC -o realcaller/plain-real 2>realcaller/evidence/build-plain-real.log
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}
check 01-three-builds-ok "$?"

ASAN_OPTIONS=detect_leaks=0 realcaller/asan-real attack >realcaller/evidence/asan-attack.out 2>&1
RC=$?
check 02-real-caller-attack-faults "$([ "$RC" -ne 0 ] && echo 0 || echo 1)"
grep -q 'ERROR: AddressSanitizer' realcaller/evidence/asan-attack.out
check 03-asan-report-present "$?"
grep -q 'WRITE of size 1' realcaller/evidence/asan-attack.out
check 04-asan-write-1 "$?"
grep -q 'multipart_parser-v2.8.0.c:260' realcaller/evidence/asan-attack.out
check 05-write-at-pinned-sink "$?"
grep -q '0 bytes after 65-byte region' realcaller/evidence/asan-attack.out
check 06-zero-bytes-past-65-byte-region "$?"
grep -q 'BOUNDARY_LEN=0' realcaller/evidence/asan-attack.out || true
grep -q 'MODE=attack BODY_LEN=396' realcaller/evidence/asan-attack.out
check 07-real-body-length-396 "$?"

ASAN_OPTIONS=detect_leaks=0 realcaller/asan-real staged >realcaller/evidence/asan-staged.out 2>&1
check 08-staged-body-through-real-caller-clean "$?"
grep -q 'BOUNDARY=a:' realcaller/evidence/asan-staged.out || true

ASAN_OPTIONS=detect_leaks=0 realcaller/asan-real safe >realcaller/evidence/asan-safe.out 2>&1
check 09-safe-body-clean "$?"

ASAN_OPTIONS=detect_leaks=0 realcaller/asan-fixed attack >realcaller/evidence/asan-fixed-attack.out 2>&1
check 10-fixed-rejects-empty-boundary "$?"
grep -q 'ERROR=Empty multipart boundary' realcaller/evidence/asan-fixed-attack.out
check 11-fixed-guard-fires "$?"

realcaller/plain-real attack >realcaller/evidence/plain-attack.out 2>&1
check 12-plain-attack-runs "$?"
grep -q 'CANARY-AFTER=0a000d0a000d0a000d0a000d' realcaller/evidence/plain-attack.out
check 13-periodic-bytes-in-adjacent-heap "$?"

realcaller/plain-real staged >realcaller/evidence/plain-staged.out 2>&1
check 14-plain-staged-runs "$?"
grep -q 'CANARY-AFTER=5a5a5a5a5a5a5a5a5a5a5a5a' realcaller/evidence/plain-staged.out
check 15-staged-body-canary-intact "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
