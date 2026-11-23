#!/bin/bash
# Persistent-connection frame-2 heap layout probe (plain build, loopback only).
# Requires build-plain-023 and live-plain from the build recipe in the report.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p results
rm -f results/gdb-multi.log results/gdb-multi-client.log
timeout 12 gdb -batch -x gdb-plain.gdb --args ./live-plain server 29441 \
  >results/gdb-multi.log 2>&1 &
spid=$!
sleep 2
timeout 6 ./live-plain client-multi 29441 >results/gdb-multi-client.log 2>&1
echo "CLIENT_RC=$?"
wait "$spid"
echo "SERVER_RC=$?"
grep -E 'PRE |POST |PROCESS_REACHED|malloc\(\)|munmap_chunk' results/gdb-multi.log
