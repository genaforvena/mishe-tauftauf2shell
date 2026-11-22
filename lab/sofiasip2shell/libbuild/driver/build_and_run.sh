#!/usr/bin/env bash
# Build the real-library driver against one pinned ASan build and run cases.
# Usage: build_and_run.sh v17 "v1.13.17" [mode ...]
# ASAN_OPTIONS_OVERRIDE may replace the ASan runtime options for the runs.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=$(cd "$HERE/.." && pwd)
PIN=$1
LABEL=$2
shift 2
MODES=${*:-full}
P="$BASE/pins/$PIN"
EVID="$BASE/evidence"
mkdir -p "$EVID"

INCS=$(find "$P/libsofia-sip-ua" -type d -name sofia-sip -printf '%h\n' | sort -u | sed 's/^/-I/' | tr '\n' ' ')
CC_CMD="clang -O0 -g -fno-omit-frame-pointer -fsanitize=address -DPIN_LABEL='\"$LABEL\"' -I$P $INCS -I$P/libsofia-sip-ua/tport $HERE/real_ws_driver.c -o $BASE/driver/$PIN-driver $P/libsofia-sip-ua/.libs/libsofia-sip-ua.a -lz -lssl -lcrypto -lpthread -lm -ldl"
{
  echo "\$ $CC_CMD"
  eval "$CC_CMD"
} > "$EVID/$PIN-driver-compile.log" 2>&1
rc=$?
if [ $rc -ne 0 ]; then
  echo "DRIVER_COMPILE_FAIL rc=$rc (see $EVID/$PIN-driver-compile.log)"
  exit $rc
fi
echo "DRIVER_COMPILE_OK $EVID/$PIN-driver-compile.log"

asan_opts=${ASAN_OPTIONS_OVERRIDE:-detect_leaks=0:abort_on_error=0}
for mode in $MODES; do
  tag="$PIN-$mode"
  run="ASAN_OPTIONS=$asan_opts $BASE/driver/$PIN-driver $mode"
  {
    echo "\$ $run"
  } > "$EVID/$tag.cmd"
  ASAN_OPTIONS="$asan_opts" "$BASE/driver/$PIN-driver" "$mode" \
    > "$EVID/$tag.out" 2> "$EVID/$tag.err"
  echo $? > "$EVID/$tag.rc"
  echo "=== $tag rc=$(cat "$EVID/$tag.rc") ==="
  cat "$EVID/$tag.out"
  grep -E 'PRECALL|POSTCALL|ERROR: AddressSanitizer|WRITE of size|READ of size|#[0-9]+ 0x|ws_read_frame|ws_raw_read|SUMMARY: AddressSanitizer' "$EVID/$tag.err" | head -40
done
