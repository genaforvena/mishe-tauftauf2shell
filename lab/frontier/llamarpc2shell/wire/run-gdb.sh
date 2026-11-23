#!/usr/bin/env bash
# Dump the live rpc_serve_client stack frame after an RDMA write.
# Non-ASan Debug build under gdb; loopback only.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIRE="$ROOT/wire"
SERVER="$ROOT/src/llama.cpp-pin-plain/bin/ggml-rpc-server"
EVID="$WIRE/evidence"
PORT=53055
CREATED=0
LEN="${LEN:-43}"
GDB_CMD="${GDB_CMD:-$WIRE/gdb-frame.cmd}"
TAG="${TAG:-gdb}"
LOG="$EVID/$TAG.log"
CLIENTLOG="$EVID/client-$TAG.log"

mkdir -p "$EVID"
g++ -std=c++17 -O0 -g "$WIRE/rdma_attacker.cpp" -libverbs -o "$WIRE/rdma_attacker" || exit 2

cleanup() {
    if [ -n "${GDB_PID:-}" ]; then
        kill "$GDB_PID" 2>/dev/null || true
        wait "$GDB_PID" 2>/dev/null || true
    fi
    if [ "$CREATED" -eq 1 ]; then
        sudo -n rdma link del rxe0 2>/dev/null || true
    fi
}
trap cleanup EXIT

if ! sudo -n rdma link show 2>/dev/null | grep -q rxe0; then
    sudo -n modprobe rdma_rxe || exit 2
    sudo -n rdma link add rxe0 type rxe netdev lo || exit 2
    CREATED=1
fi

: > "$LOG"
gdb -q --batch -x "$GDB_CMD" --args "$SERVER" -H 127.0.0.1 -p "$PORT" \
    > "$LOG" 2>&1 &
GDB_PID=$!

for _ in $(seq 1 100); do
    grep -q 'Starting RPC server' "$LOG" && break
    sleep 0.1
done
grep -q 'Starting RPC server' "$LOG" || {
    echo "gdb/server did not start" >&2
    sed -n '1,40p' "$LOG" >&2
    exit 3
}

"$WIRE/rdma_attacker" 127.0.0.1 "$PORT" "$LEN" > "$CLIENTLOG" 2>&1
CLIENT_RC=$?
for _ in $(seq 1 100); do
    grep -q 'HIT rdma_recv' "$LOG" && break
    sleep 0.1
done
sleep 1
kill "$GDB_PID" 2>/dev/null || true
wait "$GDB_PID" 2>/dev/null || true
GDB_PID=""

echo "client_rc=$CLIENT_RC payload_len=$LEN"
echo "--- client ---"
cat "$CLIENTLOG"
echo "--- gdb (frame dump) ---"
sed -n '1,120p' "$LOG"
