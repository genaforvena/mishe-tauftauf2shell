#!/usr/bin/env bash
# gdb dump runner with an identical, minimal server environment on every run.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIRE="$ROOT/wire"
EVID="$WIRE/evidence"
PORT=53058
CREATED=0
GDB_PID=""
TAG="${TAG:-fixdump}"
GDB_CMD="${GDB_CMD:-$WIRE/gdb-dump-nocanary.cmd}"
LOG="$EVID/$TAG.log"
SERVER="$ROOT/src/llama.cpp-pin-nocanary/bin/ggml-rpc-server"

cleanup() {
  if [ -n "$GDB_PID" ]; then kill "$GDB_PID" 2>/dev/null || true; wait "$GDB_PID" 2>/dev/null || true; fi
  if [ "$CREATED" -eq 1 ]; then sudo -n rdma link del rxe0 2>/dev/null || true; fi
}
trap cleanup EXIT

if ! sudo -n rdma link show 2>/dev/null | grep -q rxe0; then
  sudo -n modprobe rdma_rxe || exit 2
  sudo -n rdma link add rxe0 type rxe netdev lo || exit 2
  CREATED=1
fi
: > "$LOG"

/usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb \
  gdb -q --batch -x "$GDB_CMD" --args "$SERVER" -H 127.0.0.1 -p "$PORT" \
  > "$LOG" 2>&1 &
GDB_PID=$!
for _ in $(seq 1 100); do grep -q 'Starting RPC server' "$LOG" && break; sleep 0.1; done
RDMA_PAYLOAD_FILE="${RDMA_PAYLOAD_FILE:-}" "$WIRE/rdma_attacker" 127.0.0.1 "$PORT" "${PAYLOAD_LEN:-1}" > "$EVID/client-$TAG.log" 2>&1

CLIENT_RC=$?
for _ in $(seq 1 100); do grep -q 'HIT rdma_recv' "$LOG" && break; sleep 0.1; done
sleep 1
kill "$GDB_PID" 2>/dev/null || true; wait "$GDB_PID" 2>/dev/null || true; GDB_PID=""
echo "client_rc=$CLIENT_RC"
grep -E 'cmd address:|rpc rbp:' "$LOG"
