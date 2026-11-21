#!/bin/sh
# Bounded gdb capture of crawler/heap faults. Loopback only.
# NO breakpoints: only SIGSEGV/SIGBUS stop, so the pinned 1000 ms poll timeout
# in lru_crawler_write() is not perturbed by per-item traps.
# Usage: sh gdb-fault.sh PORT HOLD KEYBYTE KEYS [trigger.py|trigger_stress.py] [gdb-capture.gdb|gdb-capture-aslr.gdb]
set -u
cd "$(dirname "$0")" || exit 1
PORT=${1:-22160}
HOLD=${2:-150}
KEYBYTE=${3:-0x5a}
KEYS=${4:-8000}
TRIGGER=${5:-trigger.py}
GDBSCRIPT=${6:-gdb-capture.gdb}
BIN=./parent-plain/memcached
TAG="p${PORT}-$(date -u +%H%M%S)"
GDBLOG="gdb-fault-${TAG}.txt"
TRIGLOG="gdb-trigger-${TAG}.log"

cleanup() {
    pkill -f "parent-plain/memcached.*-p ${PORT} " 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python3 "$TRIGGER" "$PORT" "$KEYS" "$KEYBYTE" "$HOLD" > "$TRIGLOG" 2>&1 &
trigpid=$!
sleep 1
timeout $((HOLD + 40)) gdb -batch -x "$GDBSCRIPT" --args "$BIN" \
    -l 127.0.0.1 -p "$PORT" -U 0 -m 64 -u mesh-home \
    -o lru_crawler_sleep=0 -v > "$GDBLOG" 2>&1
grc=$?
wait $trigpid 2>/dev/null || true
printf 'gdb_rc=%s port=%s hold=%s keybyte=%s keys=%s trigger=%s gdb=%s\n' \
    "$grc" "$PORT" "$HOLD" "$KEYBYTE" "$KEYS" "$TRIGGER" "$GDBSCRIPT"
printf 'gdblog=%s triglog=%s\n' "$GDBLOG" "$TRIGLOG"
printf '%s\n' "--- gdb log key lines ---"
grep -E 'Program received signal|received signal|POST-STOP|RIP=|SIGSEGV|SIGTERM|slabs.c|assoc.c|END MARKER' \
    "$GDBLOG" | tail -20 || true
