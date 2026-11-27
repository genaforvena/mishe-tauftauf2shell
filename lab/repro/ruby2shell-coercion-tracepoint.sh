#!/bin/bash
# W323: drive loopback stock Sinatra/Rack or stock `rails new` traffic while
# the coercion observer watches every String#[]= call. No vulnerability
# trigger: every request is small and safe on both vulnerable and fixed builds.
# Usage: bash lab/repro/ruby2shell-coercion-tracepoint.sh [tag] [stock|selfcheck|rails]
set -u
cd "$(dirname "$0")/../.." || exit 1

RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
EV=lab/build/evidence
TAG="${1:-vuln-1}"
MODE="${2:-stock}"
LOG="$EV/coercion-tracepoint-$TAG.log"
OUT="$EV/coercion-tracepoint-$TAG.out"
BODY="$EV/coercion-tracepoint-$TAG.body"
mkdir -p "$EV"
rm -f "$LOG" "$OUT" "$BODY"

export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"

if [ "$MODE" = rails ]; then
  PORT=4552
  APP="${RUBY2SHELL_TP_RAILS_APP:-lab/build/rails-stock-app}"
  [ -f "$APP/config/environment.rb" ] || { echo "missing $APP" >&2; exit 2; }
  READY_URL="http://127.0.0.1:$PORT/up"
  RUBYOPT="-r$PWD/lab/repro/ruby2shell-coercion-tracepoint.rb" \
  RUBY2SHELL_TP_LOG="$PWD/$LOG" \
    "$RB" "$PWD/$APP/bin/rails" server -b 127.0.0.1 -p "$PORT" > "$OUT" 2>&1 &
else
  PORT=4551
  READY_URL="http://127.0.0.1:$PORT/health"
  RUBY2SHELL_TP_LOG="$PWD/$LOG" RUBY2SHELL_TP_PORT="$PORT" \
    "$RB" lab/repro/ruby2shell-coercion-tracepoint.rb > "$OUT" 2>&1 &
fi
SRVPID=$!
cleanup() {
  kill "$SRVPID" 2>/dev/null || true
  for _ in $(seq 1 50); do kill -0 "$SRVPID" 2>/dev/null || break; sleep 0.1; done
  kill -KILL "$SRVPID" 2>/dev/null || true
  wait "$SRVPID" 2>/dev/null || true
}
trap cleanup EXIT
READY=NO
for _ in $(seq 1 300); do
  curl -s -m 1 "$READY_URL" >/dev/null 2>&1 && { READY=YES; break; }
  sleep 0.1
done
if [ "$READY" != YES ]; then
  echo "server not ready; log:"; cat "$OUT"
  exit 1
fi

# Small safe multipart body: exercise Rack::MethodOverride + multipart charset
# tagging (2 x 0xDF bytes, far below the 21-byte overflow threshold).
python3 - > "$BODY" <<'PY'
import sys
parts = [
    b'--XB\r\nContent-Disposition: form-data; name="_method"\r\n\r\nPUT\r\n',
    b'--XB\r\nContent-Disposition: form-data; name="latin"\r\n'
    b'Content-Type: text/plain; charset=ISO-8859-1\r\n\r\n\xdf\xdf\r\n',
    b'--XB\r\nContent-Disposition: form-data; name="note"\r\n\r\nhello\r\n',
    b'--XB--\r\n',
]
sys.stdout.buffer.write(b''.join(parts))
PY

{
  echo "== $TAG mode=$MODE $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} >> "$OUT" 2>&1

case "$MODE" in
  selfcheck)
    curl -s -m 5 "http://127.0.0.1:$PORT/observer-selfcheck" \
      -w '\nselfcheck -> %{http_code}\n' >> "$OUT" 2>&1
    ;;
  rails)
    for path in /up / /rails/info/notes /missing-controller; do
      curl -s -m 10 "http://127.0.0.1:$PORT$path" -o /dev/null \
        -w "GET $path -> %{http_code}\n" >> "$OUT" 2>&1
    done
    curl -s -m 10 -X POST "http://127.0.0.1:$PORT/" \
      -H 'Content-Type: multipart/form-data; boundary=XB' \
      --data-binary @"$BODY" -o /dev/null \
      -w 'POST / multipart -> %{http_code}\n' >> "$OUT" 2>&1
    ;;
  *)
    curl -s -m 5 "http://127.0.0.1:$PORT/" -o /dev/null -w 'GET / -> %{http_code}\n' >> "$OUT" 2>&1
    curl -s -m 5 "http://127.0.0.1:$PORT/health?q=alpha&x[]=beta" -o /dev/null -w 'GET /health?q -> %{http_code}\n' >> "$OUT" 2>&1
    curl -s -m 5 -X POST "http://127.0.0.1:$PORT/echo" \
      -d 'a=1&b=two&c[]=3' -o /dev/null -w 'POST /echo urlencoded -> %{http_code}\n' >> "$OUT" 2>&1
    curl -s -m 5 -X POST "http://127.0.0.1:$PORT/trigger" \
      -H 'Content-Type: multipart/form-data; boundary=XB' \
      --data-binary @"$BODY" -o /dev/null -w 'POST /trigger multipart -> %{http_code}\n' >> "$OUT" 2>&1
    curl -s -m 5 "http://127.0.0.1:$PORT/missing-route" -o /dev/null -w 'GET /missing-route -> %{http_code}\n' >> "$OUT" 2>&1
    curl -s -m 5 "http://127.0.0.1:$PORT/health" \
      -H 'User-Agent: ruby2shell-w323-observer' -H 'Referer: http://127.0.0.1:'"$PORT"'/' \
      -o /dev/null -w 'GET /health headers -> %{http_code}\n' >> "$OUT" 2>&1
    ;;
esac

sleep 1
trap - EXIT
cleanup
echo "== $TAG server-log:" >> "$OUT"
cat "$OUT"

SUMMARY=$(grep '^SUMMARY ' "$LOG" 2>/dev/null | tail -1)
HITS=$(grep -c '^HIT ' "$LOG" 2>/dev/null || true)
[ -z "$HITS" ] && HITS=0
echo "== $TAG $SUMMARY hits-lines=$HITS"
if [ -z "$SUMMARY" ]; then
  echo 'FAIL: no SUMMARY line (observer did not flush at_exit)'
  exit 1
fi
echo "VERDICT=$([ "$HITS" -eq 0 ] && echo CLOSED || echo REOPEN)"
exit 0
