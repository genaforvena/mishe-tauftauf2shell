#!/usr/bin/env bash
# Trace why the lab marker stub classifies an entry as normal or redirected.
# Usage: probe-marker-stub.sh <outdir> <port> <index>
# Env overrides: BIN, STUB (default 0x40be40).
set -uo pipefail
OUT=${1:?usage: probe-marker-stub.sh <outdir> <port> <index>}
PORT=${2:?port required}
IDX=${3:?index required}
BIN=${BIN:-lab/frontier/vrpn2shell/build-marker-07.36/server_src/vrpn_server-marked}
STUB=${STUB:-0x40be40}
cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
set disassembly-flavor intel
break *$STUB
commands
silent
printf "STUB_HIT rsp=%p ret_at_rsp=%p\\n", \$rsp, *(void**)\$rsp
bt 4
continue
end
break *0x413dda
commands
silent
printf "RESUME_413DDA rsp=%p\\n", \$rsp
bt 3
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
echo "=== stub hits for index $IDX"
grep -E 'STUB_HIT|RESUME_413DDA|#0 |#1 |#2 |#3 |VRPN2SHELL_MARKER|Program received' "$OUT/gdb.log" | head -60
