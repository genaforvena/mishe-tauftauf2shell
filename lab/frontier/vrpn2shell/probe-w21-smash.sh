#!/usr/bin/env bash
# W21 one-off: identify the failed canary frame for wire index 512.
set -uo pipefail
OUT=${1:?outdir}
PORT=${2:?port}
IDX=${3:?index}
BIN=lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server
mkdir -p "$OUT"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:4554
commands
silent
printf "PRE i=%d name=%p dest=%p bt_follows\\n", i, sender_name, &sender_name[i]
bt 8
continue
end
break __stack_chk_fail
commands
silent
printf "SMASH rbp=%p rsp=%p\\n", \$rbp, \$rsp
x/4gx \$rbp-16
bt 6
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
grep -E 'PRE |SMASH |^#[0-9]|^0x[0-9a-f]+:|smashing|Program received' "$OUT/gdb.log" | head -70
