#!/usr/bin/env bash
# ASLR-on sweep of one-byte substr redirects. Server uses a distinct log path.
set -u
cd "$(dirname "$0")" || exit 1
CFG="$PWD/etc/proftpd-partial.conf"
BIN="${1:-../proftpd-instr}"
rm -f log/partial-server.out log/rewrite-partial.log
# Intentionally NO setarch -R.
"$BIN" -n -c "$CFG" > log/partial-server.out 2>&1 &
SRV=$!
for b in 0 1 16 32 48 64 65 80 96 112 128 144 160 176 192 208 224 240 254 255; do
  python3 client6-partial.py "$b" 2>&1
done
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null || true
echo "=== SERVER SIGNALS ==="
grep -c 'signal 11' log/partial-server.out || true
echo "=== NONEMPTY PARSE LINES AFTER MAP CALL ==="
grep -E "rewrite_parse_map_str\(\): parsing '.+'" log/rewrite-partial.log \
  | grep -v "parsing '\${u8:" | head -40 || true
