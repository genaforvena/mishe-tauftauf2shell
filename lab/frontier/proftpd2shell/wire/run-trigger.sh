#!/usr/bin/env bash
# One-shot loopback runner: starts the lab ProFTPD, issues STOR names, kills it.
set -u
cd "$(dirname "$0")" || exit 1
CFG="$PWD/etc/proftpd.conf"
BIN="${1:-../proftpd-vuln-asan}"
PORT="${2:-21874}"
export ASAN_OPTIONS="detect_leaks=0:abort_on_error=1:halt_on_error=1:log_path=$PWD/log/asan"

rm -f log/asan.* log/client-*.out
"$BIN" -n -c "$CFG" > log/server.out 2>&1 &
SRV=$!
sleep 2

python3 client.py "$PORT" 2048 > log/client-long.out 2>&1
cp log/asan.* log/long.asan.save 2>/dev/null || true
rm -f log/asan.*

python3 client.py "$PORT" 200 > log/client-short.out 2>&1
cp log/asan.* log/short.asan.save 2>/dev/null || true
rm -f log/asan.*

kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null

echo "=== LONG CLIENT (2048) ==="
cat log/client-long.out
echo "=== SHORT CLIENT (200) ==="
cat log/client-short.out
echo "=== LONG ASAN ==="
cat log/long.asan.save 2>/dev/null | head -45
echo "=== SHORT ASAN (should be empty) ==="
cat log/short.asan.save 2>/dev/null | head -20
echo "=== SERVER OUT tail ==="
tail -20 log/server.out
