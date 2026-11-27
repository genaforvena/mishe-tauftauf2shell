#!/usr/bin/env bash
# Loopback-only raw TCP ggml-rpc heap-write experiment.
# SERVER=... MODE=readback|asan|safe TAG=name bash heapwrite/run.sh
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
PORT="${PORT:-53080}"
SERVER="${SERVER:-$HERE/build-vuln/bin/ggml-rpc-server}"
MODE="${MODE:-readback}"
TAG="${TAG:-run}"
TARGET="${TARGET:-}"
CLIENT="$HERE/tcp_client"
EVID="$HERE/evidence"
mkdir -p "$EVID"
export GGML_RPC_DEBUG="${GGML_RPC_DEBUG:-1}"
if [ ! -x "$CLIENT" ] || [ "$CLIENT" -ot "$HERE/tcp_client.cpp" ]; then
    g++ -std=c++17 -O0 -g -Wall "$HERE/tcp_client.cpp" -o "$CLIENT" || exit 2
fi
SRVLOG="$EVID/$TAG-server.log"
CLILOG="$EVID/$TAG-client.log"
: > "$SRVLOG"
"$SERVER" -H 127.0.0.1 -p "$PORT" > "$SRVLOG" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true' EXIT
for i in $(seq 1 100); do
    if bash -c "exec 3<>/dev/tcp/127.0.0.1/$PORT" 2>/dev/null; then break; fi
    sleep 0.05
done
if [ -n "$TARGET" ]; then
    "$CLIENT" "$PORT" "$MODE" "$TARGET" > "$CLILOG" 2>&1
else
    "$CLIENT" "$PORT" "$MODE" > "$CLILOG" 2>&1
fi
rc=$?
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
trap - EXIT
echo "client_rc=$rc"
echo "server_sha=$(sha256sum "$SERVER" | cut -d' ' -f1)"
echo "client_sha=$(sha256sum "$CLIENT" | cut -d' ' -f1)"
echo "logs=$SRVLOG $CLILOG"
exit 0
