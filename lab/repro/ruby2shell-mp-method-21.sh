#!/bin/bash
# Wire-only Rack::MethodOverride case-conversion trigger for CVE-2026-132825.
# Loopback only. No middleware, monkey patch, debugger or memory write in the
# request path: the encoding comes from the multipart part's own Content-Type.
#
#   bash lab/repro/ruby2shell-mp-method-21.sh plain   # tracer proof of reach
#   bash lab/repro/ruby2shell-mp-method-21.sh asan    # 3.4.12 vs 3.4.13 + controls
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
MODE="${1:-asan}"
APP_MODE="${APP_MODE:-sinatra}"
EV=lab/build/evidence/mp-method-21
mkdir -p "$EV"
PORT="${RUBY2SHELL_MP_PORT:-4581}"
GEMS="$ROOT/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
export GEM_PATH="$GEMS${GEM_PATH:+:$GEM_PATH}"
APP="$ROOT/lab/repro/ruby2shell-stock-baseline.ru"
RAILS="$ROOT/lab/build/rails-stock-app/bin/rails"
SHAPES="attack safe-ascii safe-utf8 canary other-field"

run_one() {
  local name="$1" bin="$2" shape="$3" port="$4" trace="$5"
  local log="$EV/$name.server.log"
  local tracefile="$EV/$name.trace"
  local ready=NO alive=NO status="" asan=0 summary=""
  rm -f "$log" "$tracefile"
  if [ "$APP_MODE" = rails ]; then
    RUBY2SHELL_STOCK_PORT="$port" UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
      "$bin" "$RAILS" server -b 127.0.0.1 -p "$port" > "$log" 2>&1 &
  elif [ -n "$trace" ]; then
    RUBYOPT="-r$ROOT/lab/repro/ruby2shell-case-reach-trace.rb" \
    CASE_REACH_LOG="$ROOT/$tracefile" CASE_REACH_LOG_ALL=1 \
    RUBY2SHELL_STOCK_PORT="$port" UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
      "$bin" "$APP" > "$log" 2>&1 &
  else
    RUBY2SHELL_STOCK_PORT="$port" UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
      "$bin" "$APP" > "$log" 2>&1 &
  fi
  local pid=$!
  for _ in $(seq 1 300); do
    curl -s -m 1 "http://127.0.0.1:$port${APP_MODE:+$( [ "$APP_MODE" = rails ] && echo /up )}" >/dev/null 2>&1 && { ready=YES; break; }
    sleep 0.1
  done
  if [ "$ready" = YES ]; then
    status=$(python3 lab/repro/ruby2shell-mp-method-21.py "$port" "$shape")
    sleep 0.3
    kill -0 "$pid" 2>/dev/null && alive=YES || alive=NO
  fi
  asan=$(grep -c 'ERROR: AddressSanitizer' "$log" 2>/dev/null); asan=${asan:-0}
  summary=$(grep -m1 '^SUMMARY: AddressSanitizer' "$log" 2>/dev/null || echo '(none)')
  echo "$name ready=$ready alive=$alive asan=$asan summary=$summary status=$status"
  kill "$pid" 2>/dev/null
  for _ in $(seq 1 50); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill -KILL "$pid" 2>/dev/null
  wait "$pid" 2>/dev/null
}

case "$MODE" in
  plain)
    for shape in $SHAPES; do
      run_one "plain-$APP_MODE-3.4.12-$shape" lab/build/plain/ruby-3.4.12-plain/bin/ruby "$shape" "$PORT" tracer
    done
    echo "-- plain suspect upcase lines --"
    grep -h 'suspect=true' "$EV"/plain-$APP_MODE-3.4.12-*.trace 2>/dev/null | grep -v 'control=' | head -5
    ;;
  asan)
    for ver in 12 13; do
      for shape in $SHAPES; do
        run_one "asan-$APP_MODE-3.4.$ver-$shape" "lab/build/ruby-3.4.$ver-asan/bin/ruby" "$shape" "$PORT" ""
      done
    done
    ;;
  *)
    echo "usage: APP_MODE=rails bash $0 [plain|asan]" >&2; exit 2
    ;;
esac
