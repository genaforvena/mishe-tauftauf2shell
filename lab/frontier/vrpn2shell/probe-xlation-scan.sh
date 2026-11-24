#!/usr/bin/env bash
# Map every 16-byte-aligned .name slot before d_senders.d_entry[0] at the first
# addRemoteEntry() call. One benign wire message reaches the breakpoint; the
# probe quits before any memcpy, so it never mutates the process it inspects.
# Usage: probe-xlation-scan.sh <outdir> <port> [sender]
# Env overrides: BIN. No external hosts.
set -uo pipefail
OUT=${1:?usage: probe-xlation-scan.sh <outdir> <port> [sender]}
PORT=${2:?port required}
SENDER=${3:-4}
BIN=${BIN:-lab/frontier/vrpn2shell/build-plain-07.36/server_src/vrpn_server}

cd "$(dirname "$0")/../../.." || exit 2
mkdir -p "$OUT"
{
  echo "date_utc=$(date -u +%FT%TZ)"
  echo "bin=$BIN bin_sha256=$(sha256sum "$BIN")"
  echo "port=$PORT sender=$SENDER index=4 msgtype=-1"
} >"$OUT/meta.txt"
cat >"$OUT/gdb.cmd" <<EOF
set pagination off
set confirm off
source lab/frontier/vrpn2shell/w29-scan.py
break vrpn_Connection.C:405
commands
silent
python w29_scan()
end
run -f lab/frontier/vrpn2shell/vrpn.cfg $PORT
EOF
W29_HEAP_DUMP="$OUT/heap.bin" timeout 20s gdb -q -batch -x "$OUT/gdb.cmd" --args "$BIN" \
  >"$OUT/gdb.log" 2>&1 &
GPID=$!
sleep 2
python3 lab/frontier/vrpn2shell/wire_xlation.py \
  --sender "$SENDER" --index 4 --port "$PORT" --hold 1.5 \
  >"$OUT/client.txt" 2>&1
wait "$GPID" 2>/dev/null || true
echo "=== $OUT"; cat "$OUT/meta.txt" "$OUT/client.txt"
echo "=== scan lines"; grep -E 'SCAN|SLOT|Start Addr|exited' "$OUT/gdb.log" | head -80
