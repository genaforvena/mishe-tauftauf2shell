#!/bin/bash
# Wire-reachability survey for the wpqw wide-encoding lanes. Loopback only.
# Starts an unmodified stock Sinatra or `rails new` app with a Regexp-construction
# tracing preload (observability only), sends wide-encoded wire arms, and reports
# whether any default path compiled a UTF-16/32 Regexp pattern.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-sinatra}"
case "$MODE" in
  sinatra) PORT="${RUBY2SHELL_REACH_PORT:-4570}" ;;
  rails)   PORT="${RUBY2SHELL_REACH_PORT:-4572}" ;;
  *) echo "usage: $0 [sinatra|rails]" >&2; exit 2 ;;
esac
RB="lab/build/plain/ruby-3.4.12-plain/bin/ruby"
GEMS="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
export GEM_PATH="$GEMS${GEM_PATH:+:$GEM_PATH}"
EV=lab/build/evidence/wpqw-reach
mkdir -p "$EV"
LOG="$EV/$MODE.server.log"
TRACE="$EV/$MODE.trace"
WIRE="$EV/$MODE.wire"
rm -f "$LOG" "$TRACE" "$WIRE"
RUBYOPT="-r$PWD/lab/repro/ruby2shell-wpqw-reach-trace.rb" \
WPQW_REACH_LOG="$PWD/$TRACE" WPQW_REACH_LOG_ALL=1 RUBY2SHELL_STOCK_PORT="$PORT" \
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
python3 lab/repro/ruby2shell-wpqw-reach-wire.py "$PORT" all > "$WIRE" 2>&1
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
{
  echo "== wpqw wire reachability mode=$MODE ruby=$RB date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ready=$READY process-alive-after-arms=$ALIVE"
  cat "$WIRE"
  echo "-- trace summary --"
  grep -c '^boot ' "$TRACE" 2>/dev/null | sed 's/^/boot-lines=/'
  grep -c '^exit ' "$TRACE" 2>/dev/null | sed 's/^/exit-lines=/'
  grep -c '^pid=.* enc=UTF-\(16\|32\)' "$TRACE" 2>/dev/null | sed 's/^/wide-patterns=/'
  grep '^pid=.* enc=UTF-\(16\|32\)' "$TRACE" 2>/dev/null | head -20
  grep -c '^pid=.* blank-enc=UTF-\(16\|32\)' "$TRACE" 2>/dev/null | sed 's/^/wide-blank-receivers=/'
  grep '^pid=.* blank-enc=' "$TRACE" 2>/dev/null | head -10
  grep -c '^all .*bytes=.*58325348454c4c43414e415259313233' "$TRACE" 2>/dev/null | sed 's/^/canary-patterns=/'
  grep '^all .*bytes=.*58325348454c4c43414e415259313233' "$TRACE" 2>/dev/null | head -10
  echo "-- total regexp constructions --"
  grep '^exit ' "$TRACE" 2>/dev/null
} | tee "$EV/$MODE.out"
