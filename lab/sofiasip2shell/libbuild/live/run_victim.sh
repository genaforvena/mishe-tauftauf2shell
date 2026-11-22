#!/usr/bin/env bash
# Plain live WS-tport run with an LD_PRELOAD live neighbour after ws.c:1057.
# Usage: run_victim.sh <pin> <label> <port> <mode>
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BASE=$(cd "$HERE/.." && pwd)
PIN=$1 LABEL=$2 PORT=$3 MODE=$4
P="$BASE/pins/$PIN"
EVID="$BASE/evidence"
mkdir -p "$EVID"

clang -shared -fPIC -O0 -g -Wall "$HERE/victim_preload.c" -o "$HERE/libvictim.so" -ldl || exit 2
INCS=$(find "$P/libsofia-sip-ua" -type d -name sofia-sip -printf '%h\n' | sort -u | sed 's/^/-I/' | tr '\n' ' ')
clang -O0 -g -fno-omit-frame-pointer -DLIVE_VICTIM -DPIN_LABEL="\"$LABEL\"" \
  -I"$P" $INCS -I"$P/libsofia-sip-ua/tport" "$HERE/live_ws_tport.c" \
  -o "$BASE/live/$PIN-live-victim" "$HERE/libvictim.so" \
  "$P/libsofia-sip-ua/.libs/libsofia-sip-ua.a" \
  -lz -lssl -lcrypto -lpthread -lm -ldl || exit 2

tag="$PIN-live-victim-$MODE"
cmd="LD_PRELOAD=$HERE/libvictim.so $BASE/live/$PIN-live-victim $PORT $MODE"
echo "\$ $cmd" > "$EVID/$tag.cmd"
LD_PRELOAD="$HERE/libvictim.so" "$BASE/live/$PIN-live-victim" "$PORT" "$MODE" \
  > "$EVID/$tag.out" 2> "$EVID/$tag.err"
rc=$?
echo "$rc" > "$EVID/$tag.rc"
echo "=== $tag rc=$rc ==="
grep -E 'SERVER_READY|CLIENT_|VICTIM_|NEXT_SIZE|LIVE_META|TPORT_|SERVER_DONE|corrupted|ERROR:' "$EVID/$tag.err" | head -30
exit 0
