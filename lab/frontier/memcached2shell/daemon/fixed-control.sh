#!/bin/sh
# Fix-sensitivity control: same loopback stress trigger against the pinned
# fixed tree (crawler.c is its only source difference from the parent).
# Usage: sh fixed-control.sh PORT HOLD
set -u
cd "$(dirname "$0")" || exit 1
PORT=${1:-22163}
HOLD=${2:-90}
BIN=./fixed-plain/memcached
TAG="fixed-p${PORT}-$(date -u +%H%M%S)"
GDBLOG="fixed-gdb-${TAG}.txt"
TRIGLOG="fixed-trigger-${TAG}.log"
cleanup() {
    pkill -f "fixed-plain/memcached.*-p ${PORT} " 2>/dev/null || true
}
trap cleanup EXIT INT TERM
python3 trigger_stress.py "$PORT" 8000 0x5a "$HOLD" > "$TRIGLOG" 2>&1 &
trigpid=$!
sleep 1
timeout $((HOLD + 30)) gdb -batch -x gdb-capture-aslr.gdb --args "$BIN" \
    -l 127.0.0.1 -p "$PORT" -U 0 -m 64 -u mesh-home \
    -o lru_crawler_sleep=0 -v > "$GDBLOG" 2>&1
grc=$?
wait $trigpid 2>/dev/null || true
printf 'fixed_gdb_rc=%s port=%s hold=%s\n' "$grc" "$PORT" "$HOLD"
printf 'gdblog=%s triglog=%s\n' "$GDBLOG" "$TRIGLOG"
printf '%s\n' '--- fault markers (none expected) ---'
grep -E 'received signal|POST-STOP' "$GDBLOG" || true
printf '%s\n' '--- trigger tail ---'
tail -4 "$TRIGLOG"
