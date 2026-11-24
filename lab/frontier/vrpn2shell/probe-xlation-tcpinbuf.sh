#!/usr/bin/env bash
# W30: does a negative SENDER OOB record alias the live d_tcpInbuf pointer,
# and does a second TCP message consume the corrupted pointer?
# Usage: probe-xlation-tcpinbuf.sh <outdir> <port> <sender> [follow-sender]
# Env overrides: BIN, NAME, FOLLOW_NAME, INDEX. Loopback only.
set -uo pipefail
OUT=${1:?outdir}; PORT=${2:?port}; SENDER=${3:--3}; FOLLOW=${4:-4}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}
NAME=${NAME:-$(printf 'B%.0s' $(seq 96))}
FOLLOW_NAME=${FOLLOW_NAME:-$(printf 'C%.0s' $(seq 96))}
cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender=$SENDER follow=$FOLLOW index=4 msgtype=-1"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
break vrpn_Connection.C:405
commands
silent
if useEntry == $SENDER
printf "PRE405 slot=%p slotdata=%p plus8=%p plus12=%d this=%p\\n", &d_entry[useEntry], *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8), d_entry[useEntry].local_id, this
end
continue
end
break vrpn_Connection.C:4562
commands
silent
printf "DISPATCH sender_name=%s local_id=%d numSenders=%d\\n", sender_name, local_id, endpoint->d_dispatcher->d_numSenders
set \$w30i = 0
while \$w30i < endpoint->d_dispatcher->d_numSenders
printf "SENDERID[%d]=%s\\n", \$w30i, endpoint->d_dispatcher->d_senders[\$w30i]
set \$w30i = \$w30i + 1
end
continue
end
break vrpn_Connection.C:427
commands
silent
if useEntry == $SENDER
printf "POST427 slot=%p slotdata=%p plus8=%p tcpinbuf=%p remote_id=%d local_id=%d\\n", &d_entry[useEntry], *(void**)&d_entry[useEntry], *(void**)((char*)&d_entry[useEntry]+8), *(void**)((char*)this-32), d_entry[useEntry].remote_id, d_entry[useEntry].local_id
end
continue
end
break vrpn_Connection.C:4228
commands
silent
printf "GETBODY buf=%p ceil_len=%d fd=%d\\n", buf, (int)ceil_len, fd
continue
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
timeout 20s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_xlation_followup.py \
  --sender "$SENDER" --follow-sender "$FOLLOW" --port "$PORT" \
  --index "${INDEX:-4}" --name "$NAME" --follow-name "$FOLLOW_NAME" \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; cat "$OUT/meta.txt" "$OUT/client.txt"
echo "=== gdb evidence"; grep -E 'PRE405|POST427|GETBODY|DISPATCH|SENDERID|Bad address|Can.t read body|SIG|exited' "$OUT/gdb.log" | head -60
