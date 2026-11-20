#!/bin/sh
# node2shell multi-request hole inventory (wake 6, rung-4 step 1).
# One gdb process, ONE client session, two requests (LEN default 2208,
# i.e. origin 2216 — the completing regime). Break nghttp2_submit_altsvc:
# hit 1 = request 1 (records O1, walks), hit 2 = request 2 — multi_walk()
# first inventories the freed O1 hole (fd/bk, abutting chunk inuse bit),
# then walks O2. Bytes wanted: does O2 land in/abut O1's hole, and is
# the chunk following O2 free, top, or IN-USE?
#
# Usage: sh lab/repro/node2shell-shrinkwalk/run-multi.sh [port] [runs]
#   NB env override, LEN/LEN2 env overrides (authority bytes for
#   request 1 / request 2; LEN2 defaults to LEN), DELAY env override
#   (ms between requests, default 1500), MT=1 to load the committed
#   mtrace preload (lab/preload/mtrace.so) into the inferior — its
#   M/C/R/F lines then interleave with the walk markers in the gdb
#   log, giving the malloc/free timeline between the walk hits.
#   NB (wall): mtrace-env shifts the heap; sizes/order are the signal,
#   not absolute addresses.
# Loopback only; ASLR off via setarch -R.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
OUT=$ROOT/lab/node2shell/tmp/w6
NB=${NB:-$ROOT/lab/node2shell/bin/node-v24.22.2-linux-x64/bin/node}
PORT=${1:-31922}
RUNS=${2:-4}
LEN=${LEN:-2208}
LEN2=${LEN2:-$LEN}
DELAY=${DELAY:-1500}
MTOPT=""
if [ "${MT:-0}" = 1 ]; then
  MTOPT="set environment LD_PRELOAD $ROOT/lab/preload/mtrace.so"
fi
mkdir -p "$OUT"

for RUN in $(seq 1 "$RUNS"); do
  P=$((PORT + RUN))
  {
    echo "set pagination off"
    echo "source $HERE/walk.py"
    echo "set confirm off"
    echo "break nghttp2_submit_altsvc"
    echo "commands"
    echo "silent"
    echo "python multi_walk()"
    echo "continue"
    echo "end"
    echo "$MTOPT"
    echo "run $ROOT/lab/repro/node2shell-rung1-server.js $P"
    echo "bt 12"
    echo "quit"
  } > "$HERE/gsm.gdb"

  ( for i in $(seq 1 300); do "$NB" "$HERE/multi-client.js" "$P" "$LEN" "$DELAY" "$LEN2" >"$HERE/client.out" 2>&1 && break; sleep 0.2; done ) &
  CPID=$!
  timeout 40 setarch -R gdb -q -batch -x "$HERE/gsm.gdb" --args "$NB" > "$OUT/multi-run$RUN.log" 2>&1
  rc=$?
  kill $CPID 2>/dev/null
  echo "== run $RUN gdb rc=$rc client: $(cat "$HERE/client.out" 2>/dev/null | tr '\n' ';')"
  grep -E '^=== HIT|^NUL-CLASS|^O2-vs-O1|^HOLE1|^O2-VICTIM|^TOP-VICTIM|^VICTIM|^ORIGIN|SIGABRT|SIGSEGV' "$OUT/multi-run$RUN.log" | head -40
done
echo "INVENTORY-DONE logs in $OUT/"
