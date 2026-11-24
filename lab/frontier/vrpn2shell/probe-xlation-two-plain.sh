#!/usr/bin/env bash
# Debugger-free two-message loopback control runner.
# Usage: probe-xlation-two-plain.sh <outdir> <port> <sender2> <sender1> <first>
# Env: BIN, IDX. No external hosts.
set -uo pipefail
OUT=${1:?usage: probe-xlation-two-plain.sh <outdir> <port> <sender2> <sender1> <first>}
PORT=${2:?port required}
SENDER2=${3:?second sender required}
SENDER1=${4:?first sender required}
FIRST=${5:-sender}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
IDX=${IDX:-4}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender1=$SENDER1 sender2=$SENDER2 first=$FIRST index=$IDX"
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
if [ "$FIRST" = sender ]; then TS=$SENDER2; SS=$SENDER1; else TS=$SENDER1; SS=$SENDER2; fi
python3 lab/frontier/vrpn2shell/wire_xlation_two.py \
  --port "$PORT" --index "$IDX" --first "$FIRST" \
  --type-sender "$TS" --sender-sender "$SS" --hold 1.0 \
  >"$OUT/client.txt" 2>&1
sleep 1
if kill -0 "$SPID" 2>/dev/null; then
  echo "status=ALIVE_AFTER_MESSAGES" >>"$OUT/meta.txt"
  kill "$SPID" 2>/dev/null
  wait "$SPID" 2>/dev/null
else
  wait "$SPID" 2>/dev/null
  echo "status=DEAD_AFTER_MESSAGES exit=$?" >>"$OUT/meta.txt"
fi
echo "=== $OUT"; cat "$OUT/meta.txt" "$OUT/client.txt"
