#!/bin/bash
# W379: one plain vulnerable 3.4.12 Sinatra process under gdb, TWO wire
# requests, hardware watchpoints on both rb_str_casemap destinations.
# Loopback only; no debugger memory writes and no request-path middleware.
# Run from the repository root with free loopback ports.
set -u
cd "$(dirname "$0")/../.." || exit 1
PORT="${R2S_W379_PORT:-4670}"
RB="${R2S_W379_RUBY:-$PWD/lab/build/plain/ruby-3.4.12-plain/bin/ruby}"
GEMS="${R2S_W379_GEMS:-$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0}"
SURFACE="${R2S_W379_SURFACE:-method-postfield-size}"
POSTLEN="${R2S_W379_POSTLEN:-64}"
COUNT="${R2S_W379_COUNT:-2}"
TAG="${R2S_W379_TAG:-w379-primary}"
EV="${R2S_W379_EV:-lab/build/evidence/casemap-chain/w379}"
SCRIPT="$PWD/lab/repro/ruby2shell-w379-wire-watch.gdb"
mkdir -p "$EV"
OUT="$PWD/$EV/$TAG.gdb.out"
WIRE="$PWD/$EV/$TAG.wire"
export GEM_PATH="$GEMS${GEM_PATH:+:$GEM_PATH}"
export RUBY2SHELL_STOCK_PORT="$PORT"

setsid gdb -q -batch -x "$SCRIPT" --args "$RB" \
  "$PWD/lab/repro/ruby2shell-stock-baseline.ru" > "$OUT" 2>&1 &
GDB=$!
CHILD=$(pgrep -P "$GDB" | head -1)
cleanup() {
  kill -TERM "$CHILD" 2>/dev/null
  sleep 1
  kill -KILL "$GDB" 2>/dev/null
  wait "$GDB" 2>/dev/null
}
trap cleanup EXIT
READY=NO
for _ in $(seq 1 240); do
  CHILD=$(pgrep -P "$GDB" | head -1)
  if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.25
done
echo "ready=$READY child=$CHILD"
[ "$READY" = YES ] || exit 1
RUBY2SHELL_W371_SURFACES="$SURFACE" RUBY2SHELL_W377_POSTLEN="$POSTLEN" \
RUBY2SHELL_W378_COUNT="$COUNT" RUBY2SHELL_W376_RESPONSE=1 \
  python3 lab/repro/ruby2shell-w371-wire.py "$PORT" POST > "$WIRE" 2>&1
sleep 2
if kill -0 "$CHILD" 2>/dev/null; then echo "alive-after-requests=YES"; else echo "alive-after-requests=NO"; fi
grep -E '^(W379|surface=.*head=)' "$OUT"
grep -E '^surface=.*(response-len|response-sha256)' "$WIRE" | cut -c1-140
