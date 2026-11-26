#!/bin/bash
# Case-conversion wire-reachability survey for CVE-2026-132825. Loopback only.
# Starts an unmodified stock Sinatra or `rails new` app with a case-conversion
# tracer preload (observability only), sends single-byte/UTF-8 wire arms and
# reports whether any default path converts an attacker-shaped receiver.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-sinatra}"
case "$MODE" in
  sinatra) PORT="${RUBY2SHELL_CASE_PORT:-4574}" ;;
  rails)   PORT="${RUBY2SHELL_CASE_PORT:-4576}" ;;
  *) echo "usage: $0 [sinatra|rails]" >&2; exit 2 ;;
esac
RB="lab/build/plain/ruby-3.4.12-plain/bin/ruby"
GEMS="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
export GEM_PATH="$GEMS${GEM_PATH:+:$GEM_PATH}"
EV=lab/build/evidence/case-reach
mkdir -p "$EV"
LOG="$EV/$MODE.server.log"
TRACE="$EV/$MODE.trace"
WIRE="$EV/$MODE.wire"
rm -f "$LOG" "$TRACE" "$WIRE"
RUBYOPT="-r$PWD/lab/repro/ruby2shell-case-reach-trace.rb" \
CASE_REACH_LOG="$PWD/$TRACE" CASE_REACH_LOG_ALL=1 RUBY2SHELL_STOCK_PORT="$PORT" \
  "$RB" $( [ "$MODE" = rails ] && echo "$PWD/lab/build/rails-stock-app/bin/rails server -b 127.0.0.1 -p $PORT" || echo "$PWD/lab/repro/ruby2shell-stock-baseline.ru" ) \
  > "$LOG" 2>&1 &
PID=$!
cleanup() {
  if kill -0 "$PID" 2>/dev/null; then
    kill "$PID" 2>/dev/null
    for _ in $(seq 1 50); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
    kill -KILL "$PID" 2>/dev/null
  fi
  wait "$PID" 2>/dev/null
}
trap cleanup EXIT
READY=NO
for _ in $(seq 1 300); do
  URL="http://127.0.0.1:$PORT/"
  [ "$MODE" = rails ] && URL="http://127.0.0.1:$PORT/up"
  if curl -s -m 1 "$URL" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.1
done
if [ "$READY" != YES ]; then
  echo "ready=NO; see $LOG"
  exit 1
fi
python3 lab/repro/ruby2shell-case-reach-wire.py "$PORT" all > "$WIRE" 2>&1
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
{
  echo "== case-reach mode=$MODE ruby=$RB date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ready=$READY process-alive-after-arms=$ALIVE"
  cat "$WIRE"
  echo "-- trace summary --"
  grep -c '^boot ' "$TRACE" 2>/dev/null | sed 's/^/boot-lines=/'
  grep -c '^exit ' "$TRACE" 2>/dev/null | sed 's/^/exit-lines=/'
  grep '^exit ' "$TRACE" 2>/dev/null
  grep -c 'control=synthetic-0xdf-iso8859-1' "$TRACE" 2>/dev/null | sed 's/^/classifier-controls=/'
  grep -c '4341534543414e415259313233' "$TRACE" 2>/dev/null | sed 's/^/wire-canary-conversions=/'
  grep -c 'suspect=true' "$TRACE" 2>/dev/null | sed 's/^/suspect-lines=/'
  echo "-- suspect lines (first 30) --"
  grep 'suspect=true' "$TRACE" 2>/dev/null | head -30
  echo "-- wire canary lines (first 10) --"
  grep '4341534543414e415259313233' "$TRACE" 2>/dev/null | head -10
} | tee "$EV/$MODE.out"
