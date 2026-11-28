#!/bin/bash
# W369: replay ONE wire request carrying two odd sharp-s operands against an
# unmodified stock Sinatra or `rails new` app on loopback. Observability-only
# trace arms log both casecmp operands; valgrind arms count invalid writes.
set -u
cd "$(dirname "$0")/../.." || exit 1

KIND="${1:-trace}"     # trace | valgrind | plain
APP="${2:-sinatra}"    # sinatra | rails | rails-full
BUILD="${3:-vuln}"     # vuln (3.4.12) | fixed (3.4.13)
PORT="${RUBY2SHELL_W369_PORT:-4580}"
case "$KIND:$APP" in
  trace:sinatra|trace:rails|trace:rails-full|valgrind:sinatra|valgrind:rails|valgrind:rails-full|plain:sinatra) ;;
  *) echo "usage: $0 [trace|valgrind|plain] [sinatra|rails] [vuln|fixed]" >&2; exit 2 ;;
esac
case "$BUILD" in
  vuln)  RB="lab/build/plain/ruby-3.4.12-plain/bin/ruby" ;;
  fixed) RB="lab/build/plain/ruby-3.4.13-plain/bin/ruby" ;;
  *) echo "build must be vuln or fixed" >&2; exit 2 ;;
esac
[ -x "$RB" ] || { echo "missing $RB"; exit 1; }

GEMS="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
[ "$BUILD" = fixed ] && GEMS="$PWD/lab/build/plain/ruby-3.4.13-plain/lib/ruby/gems/3.4.0"
export GEM_PATH="$GEMS${GEM_PATH:+:$GEM_PATH}"
EV="lab/build/evidence/casemap-chain/w369/${KIND}-${APP}-${BUILD}"
mkdir -p "$EV"
TAG="${RUBY2SHELL_W369_TAG:-run1}"
LOG="$EV/$TAG.server.log"
TRACE="$EV/$TAG.trace"
VG="$EV/$TAG.valgrind"
WIRE="$EV/$TAG.wire"
rm -f "$LOG" "$TRACE" "$VG" "$WIRE"

case "$APP" in
  rails)      CMD=("$PWD/lab/build/rails-stock-app/bin/rails" server -b 127.0.0.1 -p "$PORT") ;;
  rails-full) CMD=("$PWD/lab/build/rails-stock-full-app/bin/rails" server -b 127.0.0.1 -p "$PORT") ;;
  *)          CMD=("$PWD/lab/repro/ruby2shell-stock-baseline.ru") ;;
esac
export RUBY2SHELL_STOCK_PORT="$PORT"
case "$KIND" in
  trace)
    export RUBYOPT="-r$PWD/lab/repro/ruby2shell-w369-casecmp-trace.rb"
    export CASE_PAIR_LOG="$PWD/$TRACE"
    CASE_PAIR_CONTROL="${CASE_PAIR_CONTROL:-1}" export CASE_PAIR_CONTROL
    ;;
  *)
    unset RUBYOPT
    ;;
esac
if [ "$KIND" = valgrind ]; then
    setsid valgrind --error-limit=no --log-file="$PWD/$VG" "$RB" "${CMD[@]}" > "$LOG" 2>&1 &
else
    setsid "$RB" "${CMD[@]}" > "$LOG" 2>&1 &
fi
PID=$!
cleanup() {
  kill -TERM -"$PID" 2>/dev/null
  for _ in $(seq 1 50); do kill -0 "$PID" 2>/dev/null || break; sleep 0.1; done
  kill -KILL -"$PID" 2>/dev/null
  wait "$PID" 2>/dev/null
}
trap cleanup EXIT

READY=NO
URL="http://127.0.0.1:$PORT/"
[ "$APP" = rails ] && URL="http://127.0.0.1:$PORT/up"
[ "$APP" = rails-full ] && URL="http://127.0.0.1:$PORT/up"
for _ in $(seq 1 600); do
  if curl -s -m 1 "$URL" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.25
done
if [ "$READY" != YES ]; then
  echo "ready=NO see $LOG"
  exit 1
fi
python3 "${RUBY2SHELL_W369_WIRE:-lab/repro/ruby2shell-w369-pair-wire.py}" "$PORT" POST > "$WIRE" 2>&1
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
{
  echo "== W369 kind=$KIND app=$APP build=$BUILD ruby=$RB date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "ready=$READY process-alive-after-one-request=$ALIVE"
  cat "$WIRE"
  if [ "$KIND" = trace ]; then
    printf 'boot-lines='; grep -c '^boot ' "$TRACE" || true
    printf 'cmp-calls='; grep -c '\(casecmp?\|casecmp\) recv' "$TRACE" || true
    printf 'both-suspect='; grep -c 'recv_suspect=true arg_suspect=true' "$TRACE" || true
    printf 'both-odd='; grep -c 'recv\[[^]]*odd=true[^]]*\] arg\[[^]]*odd=true' "$TRACE" || true
    echo "-- all casecmp operand lines --"
    grep '\(casecmp?\|casecmp\) recv' "$TRACE" | head -40
    echo "-- exit --"
    grep '^exit ' "$TRACE" || true
  fi
  if [ "$KIND" = valgrind ]; then
    printf 'invalid-writes='; grep -c 'Invalid write' "$VG" || true
    printf 'invalid-reads='; grep -c 'Invalid read' "$VG" || true
    printf 'case_map-errors='; grep -c 'case_map' "$VG" || true
    echo "-- error summary --"
    grep -E '^(==[0-9]+== )?(Invalid write|Invalid read|ERROR SUMMARY|HEAP SUMMARY)' "$VG" | head -30
  fi
} | tee "$EV/$TAG.out"
