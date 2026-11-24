#!/usr/bin/env bash
# W23 one-off: map the exact store instruction and its fault address for a
# large wire index in the stock plain -O0 server.
# Usage: probe-w23-landing.sh <outdir> <port> <index> [BIN] [ASLR]
# ASLR=on sets gdb's disable-randomization off (matches debugger-free layout).
set -uo pipefail
OUT=${1:?usage: probe-w23-landing.sh <outdir> <port> <index> [BIN]}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${4:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
ASLR=${5:-off}
ASLR_LINE=
if [ "$ASLR" = on ]; then ASLR_LINE="set disable-randomization off"; fi
mkdir -p "$OUT"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
${ASLR_LINE}
break vrpn_Connection.C:4554
commands
silent
printf "STORE i=%d rbp=%p name=%p dest=%p\\n", i, \$rbp, sender_name, &sender_name[i]
x/i \$pc
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
printf "STOP pc=%p si_addr=%p\\n", \$pc, \$_siginfo._sifields._sigfault.si_addr
x/i \$pc
bt 6
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== client"; cat "$OUT/client.txt"
echo "=== gdb"; grep -E 'STORE |STOP |Program received|SIGSEGV|SIGBUS|^#[0-9]|^0x[0-9a-f]+:|Cannot access|Error' "$OUT/gdb.log" | head -60
