#!/bin/bash
# Usage: run_gdb_case.sh <mode> <binary>
# Starts a crafted wire request in the background, then stops the real
# listener in gdb at the post-sprintf line and dumps self->done.
set -u
cd /home/mesh-home/mishe-tauftauf2shell/lab/frontier/nanomsg2shell
mode="$1"
bin="${2:-./harness/ws_server_dbg}"
safe=$(echo "$mode" | tr ':' '_')
python3 harness/wire_pattern.py 489 "$mode" 2 > "harness/client-${safe}.txt" 2>&1 &
gdb -q -batch -x harness/gdb_dump.cmd "$bin" > "harness/gdb-${safe}.txt" 2>&1
wait
echo "=== client (${mode}) ==="
cat "harness/client-${safe}.txt"
echo "=== gdb (${mode}) ==="
cat "harness/gdb-${safe}.txt"
