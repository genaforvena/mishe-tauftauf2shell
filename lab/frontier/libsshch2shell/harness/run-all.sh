#!/bin/sh
# libsshch2shell staged harness — pinned channel_rcv_data() UAF on closed channel.
# Rebuilds four variants, exercises attack/fixed/safe controls, captures evidence.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p harness/evidence
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}
notgrep() {
    if grep -q "$1" "$2"; then echo 1; else echo 0; fi
}
CFLAGS="-std=c99 -O0 -g -fno-omit-frame-pointer -I harness"

clang $CFLAGS -fsanitize=address harness/harness.c -o harness/vuln-asan 2>harness/evidence/build-vuln-asan.log
clang $CFLAGS -fsanitize=address -DLIBSSH_FIXED harness/harness.c -o harness/fixed-asan 2>harness/evidence/build-fixed-asan.log
gcc $CFLAGS -DLIBSSH_PLAIN_PROBE harness/harness.c -o harness/vuln-plain 2>harness/evidence/build-vuln-plain.log
gcc $CFLAGS -DLIBSSH_FIXED -DLIBSSH_PLAIN_PROBE harness/harness.c -o harness/fixed-plain 2>harness/evidence/build-fixed-plain.log
check 01-four-builds-ok "$?"

sha256sum -c pins.sha256 >harness/evidence/pins.out 2>&1
check 02-pins-exact "$?"

grep -q 'if (channel->flags & SSH_CHANNEL_FLAG_CLOSED_REMOTE)' harness/channel_rcv_data.inc
grep -q 'data = ssh_string_data(str);' harness/channel_rcv_data.inc
check 03-upstream-guard-and-pinned-sink-present "$?"

ASAN_OPTIONS=detect_leaks=0 harness/vuln-asan attack >harness/evidence/asan-vuln-attack.out 2>&1
RC=$?
check 04-asan-vuln-attack-faults "$([ "$RC" -ne 0 ] && echo 0 || echo 1)"
grep -q 'ERROR: AddressSanitizer: heap-use-after-free' harness/evidence/asan-vuln-attack.out
check 05-asan-heap-use-after-free "$?"
grep -q 'READ of size 32' harness/evidence/asan-vuln-attack.out
check 06-asan-read-of-32 "$?"
grep -q 'in channel_rcv_data .*channel_rcv_data.inc:85' harness/evidence/asan-vuln-attack.out
check 07-pinned-callback-frame "$?"
grep -q 'in channel_default_bufferize .*harness.c:152' harness/evidence/asan-vuln-attack.out
check 08-read-at-pinned-sink "$?"
grep -q '0 bytes inside of 64-byte region' harness/evidence/asan-vuln-attack.out
check 09-freed-64-byte-region "$?"
grep -q 'in main .*harness.c:241:9' harness/evidence/asan-vuln-attack.out
check 10-free-stack-in-driver "$?"
grep -q 'in main .*harness.c:231:30' harness/evidence/asan-vuln-attack.out
check 11-allocation-stack-in-driver "$?"

ASAN_OPTIONS=detect_leaks=0 harness/fixed-asan attack >harness/evidence/asan-fixed-attack.out 2>&1
check 12-asan-fixed-attack-clean "$?"
grep -q 'error=2' harness/evidence/asan-fixed-attack.out
check 13-upstream-guard-fires "$?"
check 14-asan-fixed-no-report "$(notgrep 'ERROR: AddressSanitizer' harness/evidence/asan-fixed-attack.out)"

ASAN_OPTIONS=detect_leaks=0 harness/vuln-asan safe >harness/evidence/asan-vuln-safe.out 2>&1
check 15-asan-safe-clean "$?"
grep -q 'error=0 callback_bytes=32' harness/evidence/asan-vuln-safe.out
check 16-safe-channel-consumes-data "$?"

ASAN_OPTIONS=detect_leaks=0 harness/fixed-asan safe >harness/evidence/asan-fixed-safe.out 2>&1
check 17-asan-fixed-safe-clean "$?"

harness/vuln-plain attack >harness/evidence/plain-vuln-attack.out 2>&1
check 18-plain-attack-runs "$?"
grep -q 'DEREF byte=M marker=MISHE-LIBSSH-UAF' harness/evidence/plain-vuln-attack.out
check 19-chosen-packet-bytes-observed "$?"

harness/fixed-plain attack >harness/evidence/plain-fixed-attack.out 2>&1
check 20-plain-fixed-attack-runs "$?"
check 21-plain-fixed-no-deref "$(notgrep 'DEREF byte' harness/evidence/plain-fixed-attack.out)"
grep -q 'error=2 callback_bytes=0' harness/evidence/plain-fixed-attack.out
check 22-plain-fixed-guard-fires "$?"

harness/vuln-plain safe >harness/evidence/plain-vuln-safe.out 2>&1
check 23-plain-safe-clean "$?"
grep -q 'DEREF byte=M marker=MISHE-LIBSSH-UAF' harness/evidence/plain-vuln-safe.out
check 24-plain-safe-payload-intact "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
