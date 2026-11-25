#!/bin/sh
# yojimbo2shell staged harness — pinned ProcessPacketFragment fragment overflow.
# Rebuilds all four variants, exercises attack/safe/fixed paths, captures evidence.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p harness/evidence
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}
CXXFLAGS="-std=c++11 -O0 -g -fno-omit-frame-pointer"

clang++ $CXXFLAGS -fsanitize=address -DYOJIMBO_EXACT_ALLOCATION harness/harness.cpp -o harness/vuln-asan 2>harness/evidence/build-vuln-asan.log
clang++ $CXXFLAGS -fsanitize=address -DYOJIMBO_EXACT_ALLOCATION -DYOJIMBO_FIXED harness/harness.cpp -o harness/fixed-asan 2>harness/evidence/build-fixed-asan.log
g++ $CXXFLAGS harness/harness.cpp -o harness/vuln-plain 2>harness/evidence/build-vuln-plain.log
g++ $CXXFLAGS -DYOJIMBO_FIXED harness/harness.cpp -o harness/fixed-plain 2>harness/evidence/build-fixed-plain.log
check 01-four-builds-ok "$?"

ASAN_OPTIONS=detect_leaks=0 harness/vuln-asan attack >harness/evidence/asan-vuln-attack.out 2>&1
RC=$?
check 02-asan-vuln-attack-faults "$([ "$RC" -ne 0 ] && echo 0 || echo 1)"
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' harness/evidence/asan-vuln-attack.out
check 03-asan-heap-buffer-overflow "$?"
grep -q 'WRITE of size 500' harness/evidence/asan-vuln-attack.out
check 04-asan-write-500 "$?"
grep -q 'ReliableOrderedChannel::ProcessPacketFragment' harness/evidence/asan-vuln-attack.out
check 05-pinned-function-in-trace "$?"
grep -q 'harness.cpp:213' harness/evidence/asan-vuln-attack.out
check 06-write-at-pinned-memcpy "$?"
grep -q '0 bytes after 1100-byte region' harness/evidence/asan-vuln-attack.out
check 07-zero-bytes-past-1100-byte-region "$?"
grep -q 'ReceiveBlockData::ReceiveBlockData' harness/evidence/asan-vuln-attack.out
check 08-allocation-from-pinned-receive-block "$?"

ASAN_OPTIONS=detect_leaks=0 harness/fixed-asan attack >harness/evidence/asan-fixed-attack.out 2>&1
check 09-asan-fixed-attack-clean "$?"
grep -q 'error=1' harness/evidence/asan-fixed-attack.out
check 10-upstream-guard-fires-desync "$?"

ASAN_OPTIONS=detect_leaks=0 harness/vuln-asan safe >harness/evidence/asan-vuln-safe.out 2>&1
check 11-asan-safe-clean "$?"
grep -q 'error=0' harness/evidence/asan-vuln-safe.out
check 12-safe-fragment-exact-fit "$?"

harness/vuln-plain attack >harness/evidence/plain-vuln-attack.out 2>&1
check 13-plain-attack-runs "$?"
grep -q 'canary0=5a' harness/evidence/plain-vuln-attack.out
check 14-plain-canary-prefix-intact "$?"
grep -q 'canary300=MISHE-OO' harness/evidence/plain-vuln-attack.out
check 15-chosen-bytes-in-adjacent-heap "$?"

harness/fixed-plain attack >harness/evidence/plain-fixed-attack.out 2>&1
check 16-plain-fixed-attack-runs "$?"
grep -q 'canary300=ZZZZZZZZ' harness/evidence/plain-fixed-attack.out
check 17-fixed-guard-leaves-canary-intact "$?"
grep -q 'error=1' harness/evidence/plain-fixed-attack.out
check 18-plain-fixed-guard-fires "$?"

grep -q 'memcpy( m_receiveBlock->blockData + fragmentId \* m_config.blockFragmentSize, fragmentData, fragmentBytes );' harness/harness.cpp
grep -q 'if ( fragmentId \* m_config.blockFragmentSize + fragmentBytes > m_config.maxBlockSize )' harness/harness.cpp
check 19-verbatim-sink-and-fix-guard-present "$?"

sha256sum -c pins.sha256 >harness/evidence/pins.out 2>&1
check 20-pins-exact "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
