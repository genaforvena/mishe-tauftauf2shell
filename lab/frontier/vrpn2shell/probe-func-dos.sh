#!/usr/bin/env bash
# Debugger-free wire probe: launch a stock plain VRPN server, send one
# SENDER_DESCRIPTION/TYPE_DESCRIPTION message, and record whether the process
# survives the unchecked NUL write. No external hosts; loopback only.
# Usage: probe-func-dos.sh <outdir> <port> <index>
# Env overrides: BIN (server binary), MSGTYPE (default -1), HOLD (default 2.0).
set -uo pipefail
OUT=${1:?usage: probe-func-dos.sh <outdir> <port> <index>}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
MSGTYPE=${MSGTYPE:--1}
HOLD=${HOLD:-2.0}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT index=$IDX msgtype=$MSGTYPE hold=$HOLD"
} >"$OUT/meta.txt"

"$BIN" -f lab/frontier/vrpn2shell/vrpn.cfg "$PORT" \
  >"$OUT/server.out" 2>"$OUT/server.err" &
SPID=$!
sleep 2
if ! kill -0 "$SPID" 2>/dev/null; then
  wait "$SPID" 2>/dev/null
  echo "status=START_FAILED exit=$?" >>"$OUT/meta.txt"
  exit 2
fi

python3 lab/frontier/vrpn2shell/wire_inject.py \
  --index "$IDX" --port "$PORT" --msgtype "$MSGTYPE" --hold "$HOLD" \
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
echo "--- server stderr (last 12)"; tail -n 12 "$OUT/server.err"
