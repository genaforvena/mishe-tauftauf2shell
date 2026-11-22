#!/usr/bin/env bash
set -u
cd "$(dirname "$0")" || exit 1
CFG="$PWD/etc/proftpd-prelogin.conf"
BIN="${1:-../proftpd-instr}"
ARCH="$(uname -m)"
rm -f log/prelogin-server.out log/rewrite-prelogin.log
setarch "$ARCH" -R "$BIN" -n -c "$CFG" > log/prelogin-server.out 2>&1 &
SRV=$!
python3 client5-prelogin.py 2>&1
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null
echo "=== SERVER ==="
grep -E 'FRONTIER_INSTR|signal 11|Login successful|session closed|NOOP command successful' log/prelogin-server.out | head -20
echo "=== REWRITE LOG ==="
grep -E 'rewrite_fixup|rewrite_subst|rewrite_parse_map_str' log/rewrite-prelogin.log 2>/dev/null | head -30 || true
