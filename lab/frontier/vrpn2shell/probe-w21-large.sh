#!/usr/bin/env bash
# W21 one-off: map the outer-frame landing of a large wire index under gdb.
# Usage: probe-w21-large.sh <outdir> <port> <index> [BIN]
set -uo pipefail
OUT=${1:?usage: probe-w21-large.sh <outdir> <port> <index> [BIN]}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${4:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
mkdir -p "$OUT"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
printf "PRE i=%d name=%p dest=%p\\n", i, sender_name, &sender_name[i]
x/16gx sender_name+$((IDX-32))
continue
end
break vrpn_Connection.C:4556
commands
silent
printf "POST i=%d dest=%p\\n", i, &sender_name[i]
x/16gx sender_name+$((IDX-32))
continue
end
break __stack_chk_fail
commands
silent
printf "STACK_CHK_FAIL_HIT\\n"
bt 12
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== client"; cat "$OUT/client.txt"
echo "=== gdb"; grep -E 'PRE |POST |STACK_CHK|Program received|^#[0-9]|smashing' "$OUT/gdb.log" | head -80
