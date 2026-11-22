#!/usr/bin/env bash
set -u
cd "$(dirname "$0")" || exit 1
CFG="$PWD/etc/proftpd.conf"
BIN="${1:-../proftpd-instr}"
ARCH="$(uname -m)"
rm -f log/marker-server.out log/rewrite.log
export ASAN_OPTIONS="detect_leaks=0"
setarch "$ARCH" -R "$BIN" -n -c "$CFG" > log/marker-server.out 2>&1 &
SRV=$!
python3 "${CLIENT:-client3.py}" 21874 2>&1
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null
echo "=== SERVER ==="
grep -E 'FRONTIER_INSTR|signal 11|Login successful|session closed|NOOP command successful' log/marker-server.out | head -20
echo "=== REWRITE LOG (marker search) ==="
grep -E 'FRONTIER_INSTR|NOOP command successful|maps subst|utf8trans' log/rewrite.log 2>/dev/null | head -20 || true
