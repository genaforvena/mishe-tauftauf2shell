#!/bin/sh
# Loopback-only fault capture with an in-process SIGSEGV/SIGBUS register shim.
# No gdb, no breakpoints, no live signals: the SIGCTX handler fires only at the
# actual fault, so the pinned 1000 ms poll() timeout is not perturbed.
# Usage: sh sigctx-fault.sh PORT HOLD KEYBYTE KEYS [trigger_stress.py]
set -u
cd "$(dirname "$0")" || exit 1
PORT=${1:-22390}
HOLD=${2:-120}
KEYBYTE=${3:-0x5a}
KEYS=${4:-8000}
TRIGGER=${5:-trigger_stress.py}
BIN=./parent-plain/memcached
SHIM="$PWD/sigctx.so"
TAG="sigctx-p${PORT}-$(date -u +%H%M%S)"
DAEMONLOG="${TAG}-daemon.log"
TRIGLOG="${TAG}-trigger.log"
ulimit -c 0

cleanup() {
    pkill -f "parent-plain/memcached.*-p ${PORT} " 2>/dev/null || true
}
trap cleanup EXIT INT TERM

python3 "$TRIGGER" "$PORT" "$KEYS" "$KEYBYTE" "$HOLD" > "$TRIGLOG" 2>&1 &
trigpid=$!
sleep 1
timeout $((HOLD + 40)) env LD_PRELOAD="$SHIM" "$BIN" \
    -l 127.0.0.1 -p "$PORT" -U 0 -m 64 -u mesh-home \
    -o lru_crawler_sleep=0 -v > "$DAEMONLOG" 2>&1
drc=$?
wait $trigpid 2>/dev/null || true
printf 'daemon_rc=%s port=%s hold=%s keybyte=%s keys=%s trigger=%s\n' \
    "$drc" "$PORT" "$HOLD" "$KEYBYTE" "$KEYS" "$TRIGGER"
printf 'daemonlog=%s triglog=%s\n' "$DAEMONLOG" "$TRIGLOG"
printf '%s\n' '--- SIGCTX records ---'
grep -E 'SIGCTX|assoc\.c|slabs\.c|Segmentation|signal [0-9]+' "$DAEMONLOG" | tail -30 || true
printf '%s\n' '--- trigger tail ---'
grep -E 'stored|metadump|allocator-driver' "$TRIGLOG" | tail -8 || true
