#!/usr/bin/env bash
# Loopback wire probe for the translation-table chosen-byte write.
# Usage: probe-xlation.sh <outdir> <port> <sender> [index]
# Env overrides: BIN, MSGTYPE, NAME, HOLD. No external hosts.
set -uo pipefail
OUT=${1:?usage: probe-xlation.sh <outdir> <port> <sender> [index]}
PORT=${2:?port required}
SENDER=${3:?sender required}
IDX=${4:-4}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
MSGTYPE=${MSGTYPE:--1}
HOLD=${HOLD:-2.0}
NAME=${NAME:-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender=$SENDER index=$IDX msgtype=$MSGTYPE hold=$HOLD"
  echo "name_sha256=$(printf %s "$NAME" | sha256sum)"
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

python3 lab/frontier/vrpn2shell/wire_xlation.py \
  --sender "$SENDER" --index "$IDX" --name "$NAME" \
  --port "$PORT" --msgtype "$MSGTYPE" --hold "$HOLD" \
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
