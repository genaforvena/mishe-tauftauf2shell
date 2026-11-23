#!/usr/bin/env bash
# W5: identify the physical heap neighbour behind the reallocated WS frame
# buffer in the live plain vulnerable tport run.  Loopback only.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=$(cd "$HERE/.." && pwd)
EVID="$BASE/evidence/w5"
mkdir -p "$EVID"

clang -shared -fPIC -O0 -g -Wall "$HERE/neighbor_probe.c" \
  -o "$HERE/libneighbor_probe.so" -ldl || exit 2

BIN="$BASE/live/v17plain-live-plain"
if [ ! -x "$BIN" ]; then
  echo "NEIGHBOR_PROBE_FAIL: missing $BIN" >&2
  exit 2
fi

run() { # tag port mode
  local tag=$1 port=$2 mode=$3
  echo "\$ LD_PRELOAD=$HERE/libneighbor_probe.so $BIN $port $mode" > "$EVID/$tag.cmd"
  LD_PRELOAD="$HERE/libneighbor_probe.so" "$BIN" "$port" "$mode" \
    > "$EVID/$tag.out" 2> "$EVID/$tag.err"
  echo $? > "$EVID/$tag.rc"
  echo "=== $tag rc=$(cat "$EVID/$tag.rc") ==="
  grep -E 'SERVER_READY|CLIENT_UPGRADE|TPORT_RECV|NEIGHBOR_|BBUF_|NEXT_SIZE|SERVER_DONE|corrupted|ERROR:' \
    "$EVID/$tag.err"
}

run v17plain-neighbor-full 18871 full
run v17plain-neighbor-short 18872 short
