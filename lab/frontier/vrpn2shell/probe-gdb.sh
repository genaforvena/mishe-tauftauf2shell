#!/usr/bin/env bash
# Loopback wire probe with a breakpoint immediately before the unchecked write.
# Prints the wire-derived index and the real frame address in the shipped server.
# Env overrides: BIN=<server binary>  LINE=<source line>  EXTRA=<gdb commands>
# VAR=<name array symbol>  MSGTYPE=<VRPN message type integer>
set -uo pipefail
OUT=${1:?usage: probe-gdb.sh <outdir> <port> <index>}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${BIN:-lab/frontier/vrpn2shell/build-asan-07.36/server_src/vrpn_server}
LINE=${LINE:-4554}
EXTRA=${EXTRA:-}
VAR=${VAR:-sender_name}
MSGTYPE=${MSGTYPE:--1}
mkdir -p "$OUT"
GDBCMD="$OUT/gdb.cmd"
cat >"$GDBCMD" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:$LINE
commands
silent
printf "WRITE_SITE_HIT i=%d &$VAR=%p dest=%p payload_len=%u\\n", i, &$VAR, &$VAR[i], p.payload_len
x/4bx p.buffer
bt 3
$EXTRA
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
ASAN_OPTIONS=detect_leaks=0 timeout 30s gdb -q -batch -x "$GDBCMD" \
  --args $BIN \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" --msgtype "$MSGTYPE" \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== client"; cat "$OUT/client.txt"
echo "=== gdb key lines"; grep -E 'WRITE_SITE_HIT|0x|ERROR: AddressSanitizer|WRITE of size|SUMMARY|vrpn_Connection.C|#0 |#1 ' "$OUT/gdb.log" | head -50
