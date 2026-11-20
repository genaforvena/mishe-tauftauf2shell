#!/usr/bin/env bash
# Rebuild and re-run the real-upstream-ws.c loopback check.
# All test traffic stays on 127.0.0.1; no off-loopback probe.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p logs

echo "=== pinned digests (unmodified upstream ws.c / ws.h) ==="
sha256sum ws/ws.c ws/ws.h ws/ws_fixed.c ws/ws_clamped.c driver.c lib/abyss/src/conn.h lib/abyss/src/session.h

gcc -g -O0 -fsanitize=address -I ws -o live_fixed ws/ws_fixed.c driver.c -lssl -lcrypto -lpthread 2>/dev/null || exit 2
gcc -g -O0 -fsanitize=address -I ws -o live_asan ws/ws.c driver.c -lssl -lcrypto -lpthread 2>/dev/null || exit 2
gcc -g -O0 -I ws -o live_plain ws/ws.c driver.c -lssl -lcrypto -lpthread 2>/dev/null || exit 2
# clamped variant: one added source-side clamp in ws_raw_read, for isolation only
gcc -g -O0 -I ws -o live_clamped ws/ws_clamped.c driver.c -lssl -lcrypto -lpthread 2>/dev/null || exit 2

echo "=== real source, ASan, 127.0.0.1 TCP socket (expect negative-size-param -5) ==="
ASAN_OPTIONS=detect_leaks=0 ./live_asan asan 2>&1 | tee logs/asan.txt
echo "asan_rc=${PIPESTATUS[0]}"

echo "=== real source, plain build (expect heap-corruption abort, rc 134) ==="
./live_plain ptr 2>&1 | tee logs/plain.txt
echo "plain_rc=${PIPESTATUS[0]}"

echo "=== fixed source (d557ca6d), ASan, 127.0.0.1 socket (expect rc=-1009, no ASan) ==="
ASAN_OPTIONS=detect_leaks=0 ./live_fixed ptr 2>&1 | tee logs/fixed.txt
echo "fixed_rc=${PIPESTATUS[0]}"
echo "fixed_check=$(grep -q 'rc=-1009' logs/fixed.txt && echo PASS || echo FAIL) (driver RESULT=FAIL is expected: it asserts chosen-pointer control)"

echo "=== clamped variant, isolation only (not a claim about real source) ==="
./live_clamped ptr 2>&1 | tee logs/clamped.txt
echo "clamped_rc=${PIPESTATUS[0]}"
