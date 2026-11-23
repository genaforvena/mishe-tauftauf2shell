#!/usr/bin/env bash
# W14: bounded extension of W11's second-order timer-heap write.
# The huge corrupted _size admits extra su_timer_set() calls; log how far
# live timer pointers reach past the 528-byte timer array and which
# allocation lives in the next chunk.  Fresh loopback ports only.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=$(cd "$HERE/.." && pwd)
EVID="$BASE/evidence/w14"
mkdir -p "$EVID"

clang -shared -fPIC -O0 -g -Wall "$HERE/timer_probe_deep.c" \
  -o "$HERE/libtimer_probe_deep.so" -ldl || exit 2

build() { # pin label
  local pin=$1 label=$2
  local P="$BASE/pins/$pin"
  local INCS
  INCS=$(find "$P/libsofia-sip-ua" -type d -name sofia-sip -printf '%h\n' | sort -u | sed 's/^/-I/' | tr '\n' ' ')
  local cmd="clang -O0 -g -fno-omit-frame-pointer -DLIVE_TIMERS -DPIN_LABEL='\"$label\"' -I$P $INCS -I$P/libsofia-sip-ua/tport $HERE/live_ws_timers_deep.c -o $BASE/live/$pin-live-timers-deep $P/libsofia-sip-ua/.libs/libsofia-sip-ua.a -lz -lssl -lcrypto -lpthread -lm -ldl"
  echo "\$ $cmd" > "$EVID/$pin-compile.log"
  eval "$cmd" >> "$EVID/$pin-compile.log" 2>&1 || {
    echo "W14_COMPILE_FAIL $pin"; tail -30 "$EVID/$pin-compile.log"; exit 2;
  }
  echo "W14_COMPILE_OK $pin"
}

run() { # pin label port mode extra
  local pin=$1 label=$2 port=$3 mode=$4 extra=$5
  local tag="$pin-$mode"
  local bin="$BASE/live/$pin-live-timers-deep"
  echo "\$ SIA_DEEP_EXTRA=$extra LD_PRELOAD=$HERE/libtimer_probe_deep.so $bin $port $mode" > "$EVID/$tag.cmd"
  SIA_DEEP_EXTRA="$extra" LD_PRELOAD="$HERE/libtimer_probe_deep.so" "$bin" "$port" "$mode" \
    > "$EVID/$tag.out" 2> "$EVID/$tag.err"
  echo $? > "$EVID/$tag.rc"
  echo "=== $tag rc=$(cat "$EVID/$tag.rc") ==="
  grep -E 'SERVER_READY|CLIENT_|TPORT_|TIMER_|DEEP_|SERVER_DONE|corrupted|SIG|Assertion|ws_read_frame|ws_raw_read' \
    "$EVID/$tag.err"
}

build v17plain v1.13.17-plain
build v18plain v1.13.18-plain
run v17plain v1.13.17-plain 19301 full 60
run v17plain v1.13.17-plain 19302 short 60
run v18plain v1.13.18-plain 19303 full 60
run v18plain v1.13.18-plain 19304 short 60
