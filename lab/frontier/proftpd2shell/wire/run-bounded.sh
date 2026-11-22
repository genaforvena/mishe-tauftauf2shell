#!/usr/bin/env bash
set -u
cd "$(dirname "$0")" || exit 1
CFG="$PWD/etc/proftpd.conf"
BIN="${1:-../proftpd-instr}"
N="${2:-1130}"
export ASAN_OPTIONS="detect_leaks=0"
rm -f log/bounded-server.out
"$BIN" -n -c "$CFG" > log/bounded-server.out 2>&1 &
SRV=$!
sleep 2
python3 client2.py 21874 "$N" 2>&1
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null
echo "=== SERVER (instr + crash) ==="
grep -E 'FRONTIER_INSTR|signal 11|STACK TRACE|pr_log_vwritefile|rewrite_subst|Login successful|session closed' log/bounded-server.out | head -30
