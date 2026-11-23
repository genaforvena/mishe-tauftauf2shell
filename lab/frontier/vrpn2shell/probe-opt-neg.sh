#!/usr/bin/env bash
# Stock -O2 frame probe for NEGATIVE wire indices. At the :4554 store the
# optimized build has rsp == rbp == &sender_name, so a negative index writes
# below rsp (the x86-64 red zone), unlike the Debug -O0 build where index -8
# hit the live `endpoint` pointer. PRE at :4554 and POST at :4560 bracket the
# store; dumps cover both sides of rsp. Loopback only.
# Usage: probe-opt-neg.sh <outdir> <port> <index>
# Env overrides: BIN, MSGTYPE, LINE_PRE, LINE_POST, VAR.
set -uo pipefail
OUT=${1:?usage: probe-opt-neg.sh <outdir> <port> <index>}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${BIN:-lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server}
MSGTYPE=${MSGTYPE:--1}
LINE_PRE=${LINE_PRE:-4554}
LINE_POST=${LINE_POST:-4560}
VAR=${VAR:-sender_name}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT index=$IDX msgtype=$MSGTYPE line_pre=$LINE_PRE line_post=$LINE_POST var=$VAR"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:$LINE_PRE
commands
silent
printf "PRE pc=%p rsp=%p rbp=%p rbx=%p i=%d dest=%p byte=0x%x\\n", \$pc, \$rsp, \$rbp, \$rbx, i, (char*)&$VAR+i, *(unsigned char*)((char*)&$VAR+i)
printf "PRE-REDZONE from rsp-128:\\n"
x/20gx \$rsp-128
printf "PRE-FRAME from rsp+128:\\n"
x/8gx \$rsp+128
bt 5
continue
end
break vrpn_Connection.C:$LINE_POST
commands
silent
printf "POST pc=%p byte=0x%x\\n", \$pc, *(unsigned char*)((char*)&$VAR+($IDX))
printf "POST-REDZONE from rsp-128:\\n"
x/20gx \$rsp-128
printf "POST-FRAME from rsp+128:\\n"
x/8gx \$rsp+128
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py \
  --index "$IDX" --port "$PORT" --msgtype "$MSGTYPE" \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; cat "$OUT/meta.txt"
echo "--- client"; cat "$OUT/client.txt"
echo "--- gdb key lines"
grep -E 'PRE |POST |REDZONE|FRAME|SIGSEGV|SIGILL|SIGABRT|exited|No symbol|not available|Optimized out|Cannot|Can.t' "$OUT/gdb.log" | head -100
