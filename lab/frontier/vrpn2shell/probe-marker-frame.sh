#!/usr/bin/env bash
# Lab-only frame probe for the no-stack-protector marker build: this frame
# places sender_name at rbp-0x80, so saved RIP is array offset 136 (not 120).
# Usage: probe-marker-frame.sh <outdir> <port> <index>
# Env overrides: BIN, LINE_POST.
set -uo pipefail
OUT=${1:?usage: probe-marker-frame.sh <outdir> <port> <index>}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${BIN:-lab/frontier/vrpn2shell/build-marker-07.36/server_src/vrpn_server}
LINE_POST=${LINE_POST:-4556}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT index=$IDX"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
set disassembly-flavor intel
break vrpn_Connection.C:4554
commands
silent
printf "PRE i=%d &name=%p rbp=%p rsp=%p rip136=%p\\n", i, &sender_name, \$rbp, \$rsp, *(void**)((char*)&sender_name+136)
x/4i \$pc
continue
end
break vrpn_Connection.C:$LINE_POST
commands
silent
printf "POST i=%d &name=%p rip136=%p\\n", i, &sender_name, *(void**)((char*)&sender_name+136)
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_inject.py --index "$IDX" --port "$PORT" \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; cat "$OUT/meta.txt"
echo "--- client"; cat "$OUT/client.txt"
echo "--- gdb key lines"; grep -E 'PRE |POST |SIGSEGV|SIGILL|SIGABRT|Program received|=>|rip136' "$OUT/gdb.log" | head -40
