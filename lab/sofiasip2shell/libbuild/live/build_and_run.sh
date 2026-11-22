#!/usr/bin/env bash
# Build and run the live WS-tport driver against one pinned library.
# Usage: SAN=asan|plain build_and_run.sh <pin> <label> [port]
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=$(cd "$HERE/.." && pwd)
PIN=$1
LABEL=$2
PORT=${3:-18857}
SAN=${SAN:-asan}
SUFFIX=
RUN_PREFIX=()
if [ "$SAN" = plain ]; then
  SAN_FLAGS=
  SUFFIX=-plain
else
  SAN_FLAGS='-fsanitize=address'
  RUN_PREFIX=(env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0)
fi
P="$BASE/pins/$PIN"
EVID="$BASE/evidence"
mkdir -p "$EVID"

INCS=$(find "$P/libsofia-sip-ua" -type d -name sofia-sip -printf '%h\n' | sort -u | sed 's/^/-I/' | tr '\n' ' ')
CC_CMD="clang -O0 -g -fno-omit-frame-pointer $SAN_FLAGS -DPIN_LABEL='\"$LABEL\"' -I$P $INCS -I$P/libsofia-sip-ua/tport $HERE/live_ws_tport.c -o $BASE/live/$PIN-live$SUFFIX $P/libsofia-sip-ua/.libs/libsofia-sip-ua.a -lz -lssl -lcrypto -lpthread -lm -ldl"
{
  echo "\$ $CC_CMD"
  eval "$CC_CMD"
} > "$EVID/$PIN-live$SUFFIX-compile.log" 2>&1
rc=$?
if [ $rc -ne 0 ]; then
  echo "LIVE_COMPILE_FAIL rc=$rc (see $EVID/$PIN-live$SUFFIX-compile.log)"
  tail -40 "$EVID/$PIN-live$SUFFIX-compile.log"
  exit $rc
fi
echo "LIVE_COMPILE_OK $EVID/$PIN-live$SUFFIX-compile.log"

for mode in full short; do
  tag="$PIN-live$SUFFIX-$mode"
  bin="$BASE/live/$PIN-live$SUFFIX"
  if [ ${#RUN_PREFIX[@]} -gt 0 ]; then
    run="${RUN_PREFIX[*]} $bin $PORT $mode"
  else
    run="$bin $PORT $mode"
  fi
  {
    echo "\$ $run"
  } > "$EVID/$tag.cmd"
  "${RUN_PREFIX[@]}" "$BASE/live/$PIN-live$SUFFIX" "$PORT" "$mode" \
    > "$EVID/$tag.out" 2> "$EVID/$tag.err"
  echo $? > "$EVID/$tag.rc"
  echo "=== $tag rc=$(cat "$EVID/$tag.rc") ==="
  grep -E 'SERVER_READY|CLIENT_|TPORT_|SERVER_DONE|ERROR: AddressSanitizer|READ of size|WRITE of size|ws_read_frame|ws_raw_read|SUMMARY:|ws.c:' "$EVID/$tag.err" | head -40
done
