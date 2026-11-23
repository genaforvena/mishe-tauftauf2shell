#!/bin/bash
# Replay one crafted KV-header frame against a loopback Thrift server.
# Usage: ./run-kv.sh FRAME [PORT] [SERVER_BINARY]
set -u
cd "$(dirname "$0")" || exit 1
frame="$1"
port="${2:-29391}"
server="${3:-./live-plain}"
log="results/kv-$(basename "$frame" .bin).log"
mkdir -p results
rm -f "$log"
timeout 8 "$server" server "$port" >"$log" 2>&1 &
spid=$!
sleep 1
python3 raw-client.py "$port" "$frame"
wait "$spid"
src=$?
echo "SERVER_RC=$src LOG=$log"
sed -n '1,12p' "$log"
