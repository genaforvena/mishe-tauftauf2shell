#!/bin/bash
# Run the keep-alive client under a gdb observer on the case-map overflow.
# Harness-only observation, not part of any rung-5 claim. Loopback only.
set -u
cd "$(dirname "$0")/../.." || exit 1
MODE="${1:-attack}"
TAG="${2:-webrick-keep-watch-$MODE}"
FILL="${RUBY2SHELL_KEEP_FILL:-40}"
N="${3:-572}"
GS="${RUBY2SHELL_GDB_SCRIPT:-lab/repro/ruby2shell-webrick-keep-watch.gdb}"
PORT=4552
EV=lab/build/evidence
OUT="$EV/stock-baseline-$TAG.out"
LOG="$EV/stock-baseline-$TAG.server.log"
mkdir -p "$EV"
FIFO="$EV/.keep-watch-fifo-$$"
rm -f "$FIFO"
mkfifo "$FIFO"
export RUBY2SHELL_WATCH_N="$N" RUBY2SHELL_WATCH_PORT="$PORT" RUBY2SHELL_KEEP_FILL="$FILL"
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0${GEM_PATH:+:$GEM_PATH}"
gdb -q -batch \
  -x "$GS" \
  --args lab/build/plain/ruby-3.4.12-plain/bin/ruby \
  lab/repro/ruby2shell-stock-baseline.ru -s webrick < "$FIFO" > "$LOG" 2>&1 &
GDB=$!
exec 9>"$FIFO"
READY=NO
for _ in $(seq 1 300); do
  if curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1; then READY=YES; break; fi
  sleep 0.1
done
if [ "$READY" = YES ]; then
  python3 lab/repro/ruby2shell-webrick-keep-client.py "$MODE" "$FILL" "$PORT" "$N" > "$OUT" 2>&1
else
  echo 'server not ready' > "$OUT"
fi
sleep 1
printf 'kill\nquit\n' >&9
exec 9>&-
wait "$GDB" 2>/dev/null
rm -f "$FIFO"
echo "== $TAG mode=$MODE n=$N fill=$FILL ready=$READY gdb=$GS"
cat "$OUT"
echo '--- gdb observer log ---'
grep -m 80 -E 'ATTACK|ALLOC|OVERLAP|ABORT|Python Exception|Error' "$LOG"
