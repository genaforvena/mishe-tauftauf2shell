#!/bin/bash
# Run a loopback server under gdb while replaying one crafted KV frame.
# Usage: ./run-kv-gdb.sh FRAME [GDB_SCRIPT] [PORT] [HOLD_SECONDS]
set -u
cd "$(dirname "$0")" || exit 1
frame="$1"
script="${2:-gdb-kv.gdb}"
port="${3:-29392}"
hold="${4:-0}"
log="results/kv-gdb-$(basename "$frame" .bin).log"
mkdir -p results
rm -f "$log"
gdb -q -batch -x "$script" --args ./live-plain server "$port" >"$log" 2>&1 &
gpid=$!
sleep 1
python3 raw-client.py "$port" "$frame" "$hold"
wait "$gpid"
grc=$?
echo "GDB_RC=$grc LOG=$log"
sed -n '1,16p' "$log"
