#!/usr/bin/env bash
set -u
cd "$(dirname "$0")" || exit 1
CFG="$PWD/etc/proftpd-partial.conf"
BIN="${1:-../proftpd-instr}"
rm -f log/partial-server.out log/rewrite-partial.log
# Intentionally NO setarch -R.
"$BIN" -n -c "$CFG" > log/partial-server.out 2>&1 &
SRV=$!
python3 client6-partial.py 65 200 2>&1
python3 client6-partial.py 65 1025 2>&1
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null || true
echo "=== PARSE LINES (trimmed) ==="
grep 'rewrite_parse_map_str(): parsing ' log/rewrite-partial.log | cut -c1-150
