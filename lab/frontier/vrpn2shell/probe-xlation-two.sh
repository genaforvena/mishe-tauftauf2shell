#!/usr/bin/env bash
# gdb map of two translation-table writes on one loopback connection.
# Usage: probe-xlation-two.sh <outdir> <port> <sender2> [sender1]
# Env overrides: BIN, INDEX. No external hosts.
set -uo pipefail
OUT=${1:?usage: probe-xlation-two.sh <outdir> <port> <sender2> [sender1]}
PORT=${2:?port required}
SENDER2=${3:?second-message sender required}
SENDER1=${4:-2}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
IDX=${IDX:-4}
FIRST=${FIRST:-type}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender1=$SENDER1 sender2=$SENDER2 index=$IDX first=$FIRST"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:405
commands
silent
printf "AT405 this=%p d_entry=%p useEntry=%d remote_id=%d local_id=%d name=%p\\n", this, d_entry, useEntry, remote_id, local_id, name
x/2gx &d_entry[useEntry]
continue
end
break vrpn_Connection.C:414
commands
silent
printf "PRE414 useEntry=%d dest=%p name=%p\\n", useEntry, d_entry[useEntry].name, name
x/16bx d_entry[useEntry].name
continue
end
break vrpn_Connection.C:415
commands
silent
printf "POST415 useEntry=%d dest=%p\\n", useEntry, d_entry[useEntry].name
x/16bx d_entry[useEntry].name
bt 3
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
if [ "$FIRST" = sender ]; then
  TS=$SENDER2; SS=$SENDER1
else
  TS=$SENDER1; SS=$SENDER2
fi
python3 lab/frontier/vrpn2shell/wire_xlation_two.py \
  --port "$PORT" --index "$IDX" --first "$FIRST" \
  --type-sender "$TS" --sender-sender "$SS" --hold 2.0 \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; cat "$OUT/meta.txt" "$OUT/client.txt"
echo "=== gdb key lines"
grep -E 'AT405|PRE414|POST415|Program received|SIGSEGV|SIGBUS|SIGILL|exited' "$OUT/gdb.log" | head -60
