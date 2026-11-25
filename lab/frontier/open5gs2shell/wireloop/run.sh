#!/bin/sh
# Loopback HTTP/2 wire replay. Does not change the staged or real-caller
# suites; builds three shims from the same pinned source in ../realcaller/.
set -u
cd "$(dirname "$0")/.." || exit 1
mkdir -p wireloop/evidence
CFLAGS="-O0 -g -Irealcaller -Iharness -Iprovision"
SRC="realcaller/realcaller.c provision/multipart_parser-v2.8.0.c"

cc $CFLAGS -fsanitize=address $SRC -o wireloop/asan-wire \
    2>wireloop/evidence/build-asan.log
cc $CFLAGS -fsanitize=address -DFIXED_BUILD $SRC -o wireloop/fixed-wire \
    2>wireloop/evidence/build-fixed.log
cc $CFLAGS $SRC -o wireloop/plain-wire \
    2>wireloop/evidence/build-plain.log
PASS=0
FAIL=0
check() {
    if [ "$2" -eq 0 ]; then PASS=$((PASS+1)); echo "PASS-$1"; else FAIL=$((FAIL+1)); echo "FAIL-$1"; fi
}
check 01-three-builds-ok "$?"

cd wireloop || exit 1
ASAN_OPTIONS=detect_leaks=0 go run wire.go \
    "$PWD/asan-wire" "$PWD/fixed-wire" "$PWD/plain-wire" \
    >evidence/wire.out 2>&1
check 02-wire-driver-exit "$?"

grep -q 'LISTENER addr=https://127.0.0.1:' evidence/wire.out
check 03-loopback-tls-listener "$?"
grep -q 'WIRE case=attack-asan proto=HTTP/2.0 len=396 head=0d0a0d0a613a0d0a0d0a' evidence/wire.out
check 04-exact-attack-body-over-h2 "$?"
grep -q 'BOUNDARY_LEN=0 BOUNDARY=' evidence/wire.out
check 05-wire-body-yields-empty-boundary "$?"
grep -q 'WRITE of size 1' evidence/wire.out
check 06-asan-write-from-wire "$?"
grep -q 'multipart_parser-v2.8.0.c:260' evidence/wire.out
check 07-write-at-pinned-sink "$?"
grep -q 'CANARY-AFTER=0a000d0a000d0a000d0a000d' evidence/wire.out
check 08-periodic-bytes-from-wire "$?"

grep -q 'WIRE case=staged-asan proto=HTTP/2.0 len=394' evidence/wire.out
check 09-staged-body-over-h2 "$?"
grep -q 'BOUNDARY=a:' evidence/wire.out
check 10-staged-body-has-nonempty-boundary "$?"
grep -q 'WIRE case=safe-asan proto=HTTP/2.0 len=10' evidence/wire.out
check 11-safe-body-over-h2 "$?"
grep -q 'ERROR=Empty multipart boundary' evidence/wire.out
check 12-fixed-guard-rejects-wire-attack "$?"
grep -q 'RESULT wire-failures=0' evidence/wire.out
check 13-all-responses-h2-200 "$?"

echo "RESULT $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
