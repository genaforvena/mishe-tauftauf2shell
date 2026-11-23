#!/usr/bin/env bash
# W11: bounded second-order timer-heap probe on the live loopback WS tport.
# Pre-queues 30 timers (heap capacity), sends the real masked frame, then
# two more su_timer_set() calls before any allocator operation.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=$(cd "$HERE/.." && pwd)
EVID="$BASE/evidence/w11"
mkdir -p "$EVID"

clang -shared -fPIC -O0 -g -Wall "$HERE/timer_probe.c" \
  -o "$HERE/libtimer_probe.so" -ldl || exit 2

build() { # pin label
  local pin=$1 label=$2
  local P="$BASE/pins/$pin"
  local INCS
  INCS=$(find "$P/libsofia-sip-ua" -type d -name sofia-sip -printf '%h\n' | sort -u | sed 's/^/-I/' | tr '\n' ' ')
  local cmd="clang -O0 -g -fno-omit-frame-pointer -DLIVE_TIMERS -DPIN_LABEL='\"$label\"' -I$P $INCS -I$P/libsofia-sip-ua/tport $HERE/live_ws_timers.c -o $BASE/live/$pin-live-timers $P/libsofia-sip-ua/.libs/libsofia-sip-ua.a -lz -lssl -lcrypto -lpthread -lm -ldl"
  echo "\$ $cmd" > "$EVID/$pin-compile.log"
  eval "$cmd" >> "$EVID/$pin-compile.log" 2>&1 || {
    echo "W11_COMPILE_FAIL $pin"; tail -30 "$EVID/$pin-compile.log"; exit 2;
  }
  echo "W11_COMPILE_OK $pin"
}

run() { # pin label port mode
  local pin=$1 label=$2 port=$3 mode=$4
  local tag="$pin-$mode"
  local bin="$BASE/live/$pin-live-timers"
  echo "\$ LD_PRELOAD=$HERE/libtimer_probe.so $bin $port $mode" > "$EVID/$tag.cmd"
  LD_PRELOAD="$HERE/libtimer_probe.so" "$bin" "$port" "$mode" \
    > "$EVID/$tag.out" 2> "$EVID/$tag.err"
  echo $? > "$EVID/$tag.rc"
  echo "=== $tag rc=$(cat "$EVID/$tag.rc") ==="
  grep -E 'SERVER_READY|CLIENT_|TPORT_|TIMER_|SERVER_DONE|corrupted|SIG|Assertion|ws_read_frame|ws_raw_read' \
    "$EVID/$tag.err"
}

build v17plain v1.13.17-plain
build v18plain v1.13.18-plain
run v17plain v1.13.17-plain 18901 full
run v17plain v1.13.17-plain 18902 short
run v18plain v1.13.18-plain 18903 full
run v18plain v1.13.18-plain 18904 short
