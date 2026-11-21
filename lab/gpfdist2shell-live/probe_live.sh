#!/usr/bin/env bash
# Live loopback probe of the REAL pinned gpfdist.c (ASan build, shimmed I/O).
# All traffic stays on 127.0.0.1. One process per case; ASan aborts on fault.
set -u
HERE=$(cd "$(dirname "$0")" && pwd)
BIN=${1:-$HERE/gpfdist_v7.6.1_asan}
PORT=${2:-18088}
CASE=${3:-both}
TAG=$(basename "$BIN")_${CASE}
OUT="$HERE/out_$TAG"
mkdir -p "$OUT"
DATA="$OUT/data"
mkdir -p "$DATA"
printf 'row1\nrow2\n' > "$DATA/data.txt"
: > "$DATA/out.txt"
LOG="$OUT/server.log"
ASAN="$OUT/asan"
: > "$LOG"
export ASAN_OPTIONS="abort_on_error=1:detect_leaks=0:log_path=$ASAN"
"$BIN" -b 127.0.0.1 -p "$PORT" -d "$DATA" -l "$LOG" >"$OUT/stdout.log" 2>&1 &
PID=$!
for i in $(seq 1 40); do
  if (echo >"/dev/tcp/127.0.0.1/$PORT") >/dev/null 2>&1; then break; fi
  sleep 0.1
done
if ! kill -0 "$PID" 2>/dev/null; then
  echo "SERVER_FAILED_TO_START"
  cat "$OUT/stdout.log" | sed -n 1,40p
  exit 2
fi
echo "SERVER_PID=$PID PORT=$PORT"
HOSTILE_SEQ=4702111234474983745
run_case() {
  local desc="$1"; shift
  local code
  code=$(curl -sS -m 5 -o "$OUT/${desc}.body" -w '%{http_code}' "$@" 2>"$OUT/${desc}.curlerr")
  local rc=$?
  echo "CASE $desc http=$code curlrc=$rc"
  if [ -f "$OUT/${desc}.curlerr" ]; then sed -n 1,3p "$OUT/${desc}.curlerr"; fi
}
if [ "$CASE" = "both" ] || [ "$CASE" = "active" ]; then
  run_case active_get -X GET "http://127.0.0.1:$PORT/data.txt" \
    -H 'X-GP-PROTO:1' -H 'X-GP-SEGMENT-COUNT:1' -H 'X-GP-SEGMENT-ID:3'
  sleep 0.5
  if ! kill -0 "$PID" 2>/dev/null; then echo "SERVER_DIED_AFTER_ACTIVE_GET"; fi
fi
if kill -0 "$PID" 2>/dev/null && { [ "$CASE" = "both" ] || [ "$CASE" = "seq" ]; }; then
  run_case seq_post -X POST "http://127.0.0.1:$PORT/out.txt" \
    -H 'X-GP-PROTO:1' -H 'X-GP-SEGMENT-COUNT:1' -H 'X-GP-SEGMENT-ID:3' \
    -H "X-GP-SEQ:$HOSTILE_SEQ"
  sleep 0.5
  if ! kill -0 "$PID" 2>/dev/null; then echo "SERVER_DIED_AFTER_SEQ_POST"; fi
fi
if kill -0 "$PID" 2>/dev/null; then kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; fi
echo "--- server.log ---"; sed -n 1,60p "$LOG"
echo "--- asan files ---"; ls -la "$OUT"/asan* 2>&1 | sed -n 1,20p
for f in "$OUT"/asan*; do [ -f "$f" ] && { echo "--- $f ---"; sed -n 1,80p "$f"; }; done
