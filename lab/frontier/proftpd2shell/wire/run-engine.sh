#!/usr/bin/env bash
# A/B: ENGINE_ZERO=1 zeroes rewrite_engine via the utf8trans OOB write;
# ENGINE_ZERO=0 leaves it on. Compare RewriteLog lines for the short STOR.
set -u
cd "$(dirname "$0")" || exit 1
CFG="$PWD/etc/proftpd.conf"
BIN="${1:-../proftpd-instr}"
ARCH="$(uname -m)"
TAG="${TAG:-engine-$(date -u +%Y%m%dT%H%M%SZ)}"
OUT="evidence/$TAG.txt"
mkdir -p evidence
rm -f log/marker-server.out log/rewrite.log
export ASAN_OPTIONS="detect_leaks=0"
setarch "$ARCH" -R "$BIN" -n -c "$CFG" > log/marker-server.out 2>&1 &
SRV=$!
CLIENT="${CLIENT:-client7-engine.py}"
python3 "$CLIENT" 21874 2>&1 | tee "$OUT"
kill "$SRV" 2>/dev/null
wait "$SRV" 2>/dev/null
{
  echo "=== SERVER ($TAG) ==="
  grep -E 'FRONTIER_INSTR|signal 11|Login successful|session closed|NOOP command successful' log/marker-server.out | head -20
  echo "=== REWRITE LOG ($TAG) ==="
  grep -E 'FRONTIER_INSTR|NOOP command successful|maps subst|utf8trans|executing RewriteRule|skipping' log/rewrite.log 2>/dev/null | head -40 || true
  echo "=== SHORT-STOR REWRITE LINES ($TAG) ==="
  grep -nE 'executing RewriteRule|maps subst|rule backref|var subst' log/rewrite.log 2>/dev/null | tail -20 || true
} | tee -a "$OUT"
cp log/rewrite.log "evidence/rewrite-$TAG.log" 2>/dev/null || true
cp log/marker-server.out "evidence/server-$TAG.out" 2>/dev/null || true
