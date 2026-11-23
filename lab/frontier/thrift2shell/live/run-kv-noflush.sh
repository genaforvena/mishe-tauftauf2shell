#!/bin/bash
# Replay one KV frame against the lab-only no-flush server under gdb with
# ASLR on (the gdb script controls randomization). Loopback only.
# Usage: ./run-kv-noflush.sh FRAME [GDB_SCRIPT] [PORT] [HOLD_SECONDS]
set -u
cd "$(dirname "$0")" || exit 1
frame="$1"
script="${2:-gdb-kv-partial.gdb}"
port="${3:-29480}"
hold="${4:-1}"
server="${NOFLUSH_SERVER:-./live-noflush}"
log="results/kv-noflush-$(basename "$server" .bin)-$(basename "$frame" .bin).log"
mkdir -p results
rm -f "$log"
timeout 25 gdb -q -batch -x "$script" --args "$server" server-noflush "$port" >"$log" 2>&1 &
gpid=$!
sleep 1
python3 raw-client.py "$port" "$frame" "$hold"
wait "$gpid"
grc=$?
echo "GDB_RC=$grc LOG=$log"
grep -E 'PRE |POST |FREE mem=|PROCESS_REACHED|Program received|invalid|corrupt|unaligned|SIGSEGV|ERROR' "$log" | tail -20 || true
