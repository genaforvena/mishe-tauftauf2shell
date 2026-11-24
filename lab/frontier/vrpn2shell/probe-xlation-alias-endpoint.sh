#!/usr/bin/env bash
# Verify the sender=-2 OOB record aliases endpoint pointer fields.
# Usage: probe-xlation-alias-endpoint.sh <outdir> <port> [-1|-2]
# Env overrides: BIN. No external hosts.
set -uo pipefail
OUT=${1:?outdir}; PORT=${2:?port}; SENDER=${3:--2}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender=$SENDER index=4 msgtype=-1"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:414
commands
silent
if useEntry == $SENDER
printf "PRE414 slot=%p name=%p remote_id=%d local_id=%d slotdata=%p plus8=%p\\n", &d_entry[useEntry], d_entry[useEntry].name, d_entry[useEntry].remote_id, d_entry[useEntry].local_id, *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8)
x/16bx d_entry[useEntry].name
end
continue
end
break vrpn_Connection.C:427
commands
silent
if useEntry == $SENDER
printf "POST427 slot=%p slotdata=%p plus8=%p remote_id=%d local_id=%d\\n", &d_entry[useEntry], *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8), d_entry[useEntry].remote_id, d_entry[useEntry].local_id
x/16bx *(char**)((char*)&d_entry[useEntry])
bt 3
end
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 20s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_xlation.py --sender "$SENDER" --index 4 --port "$PORT" --hold 1.5 >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; grep -E 'PRE414|POST427|SIG|exited|0x555555' "$OUT/gdb.log" | head -30
