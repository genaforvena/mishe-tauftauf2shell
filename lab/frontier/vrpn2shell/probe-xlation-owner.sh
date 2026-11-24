#!/usr/bin/env bash
# Identify the live object whose field is aliased by d_entry[-2].name.
# Usage: probe-xlation-owner.sh <outdir> <port>
set -uo pipefail
OUT=${1:?outdir}; PORT=${2:?port}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender=4 index=4"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
set max-value-size 100000
break vrpn_Connection.C:405
commands
silent
printf "AT405 base=%p slot=%p value=%p useEntry=%d\\n", &d_entry[0], &d_entry[-2], d_entry[-2].name, useEntry
bt 5
up 2
printf "UP2 fn=%s\\n", __func__
p endpoint
p/x (unsigned long)endpoint + 65840
p/x (unsigned long)&((vrpn_Endpoint_IP*)endpoint)->d_tcpInbuf
p/x (unsigned long)((vrpn_Endpoint_IP*)endpoint)->d_tcpInbuf
p/x (unsigned long)&((vrpn_Endpoint_IP*)endpoint)->d_tcpAlignedInbuf[0]
quit
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 20s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_xlation.py --sender 4 --index 4 --port "$PORT" --hold 1.5 >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; grep -E 'AT405|UP2|^[0-9]+|\\\$\[0-9\]|endpoint|d_tcp|SIG|exited' "$OUT/gdb.log" | head -40
