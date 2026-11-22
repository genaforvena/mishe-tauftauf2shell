#!/usr/bin/env bash
# Loopback wire test with a gdb breakpoint on the vulnerable system handler.
set -uo pipefail
OUT=${1:?usage: gdb-wire.sh <outdir>}
PORT=${2:-13896}
IDX=${3:--64}
mkdir -p "$OUT"
GDBCMD="$OUT/gdb.cmd"
cat >"$GDBCMD" <<EOF
set pagination off
set confirm off
break vrpn_Endpoint::handle_sender_message
commands
silent
printf "HANDLER_HIT sender\\n"
bt 4
continue
end
break vrpn_Endpoint::handle_type_message
commands
silent
printf "HANDLER_HIT type\\n"
bt 4
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
ASAN_OPTIONS=detect_leaks=0 timeout 25s gdb -q -batch -x "$GDBCMD" \
  --args lab/frontier/vrpn2shell/build-asan-07.36/server_src/vrpn_server \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== client"; cat "$OUT/client.txt"
echo "=== gdb hits"; grep -E 'HANDLER_HIT|#0 |#1 |#2 ' "$OUT/gdb.log" | head -30
echo "=== gdb tail"; tail -12 "$OUT/gdb.log"
