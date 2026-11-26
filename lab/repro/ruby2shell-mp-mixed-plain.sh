#!/bin/bash
# Wire-only parity-flip arms on the plain (no sanitizer) stock-glibc build.
# Each arm gets a fresh unmodified classic Sinatra server on loopback.
#   bash lab/repro/ruby2shell-mp-mixed-plain.sh [repetitions]
# Evidence: lab/build/evidence/mp-method-21/ (gitignored).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
REPS="${1:-8}"
EV=lab/build/evidence/mp-method-21
mkdir -p "$EV"
PORT="${RUBY2SHELL_MP_PORT:-4583}"
GEMS="$ROOT/lab/build/plain/ruby-3.4.12-plain/lib/ruby/gems/3.4.0"
export GEM_PATH="$GEMS${GEM_PATH:+:$GEM_PATH}"
APP="$ROOT/lab/repro/ruby2shell-stock-baseline.ru"
SHAPES="pure20 pure21 mixed27 mixed43 mixed59 mixed43-utf8"

for ver in 12 13; do
  [ "$ver" = 13 ] && reps=2 || reps="$REPS"
  for shape in $SHAPES; do
    for rep in $(seq 1 "$reps"); do
      bin="lab/build/plain/ruby-3.4.$ver-plain/bin/ruby"
      log="$EV/plain-$ver-$shape-$rep.server.log"
      rm -f "$log"
      RUBY2SHELL_STOCK_PORT="$PORT" "$bin" "$APP" > "$log" 2>&1 &
      pid=$!
      ready=NO
      for _ in $(seq 1 200); do
        curl -s -m 1 "http://127.0.0.1:$PORT/" >/dev/null 2>&1 && { ready=YES; break; }
        sleep 0.1
      done
      alive=NA status=NA glibc=none
      if [ "$ready" = YES ]; then
        status=$(python3 lab/repro/ruby2shell-mp-method-21.py "$PORT" "$shape")
        sleep 0.2
        kill -0 "$pid" 2>/dev/null && alive=YES || alive=NO
        glibc=$(grep -m1 -E 'corrupted size|invalid pointer|free\(\): |malloc\(\): |double free|Segmentation fault|\[BUG\]' "$log" || echo none)
      fi
      echo "3.4.$ver $shape rep=$rep ready=$ready alive=$alive glibc=$glibc status=$status" | tee "$EV/plain-$ver-$shape-$rep.out"
      kill "$pid" 2>/dev/null
      for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
      kill -KILL "$pid" 2>/dev/null
      wait "$pid" 2>/dev/null
    done
  done
done
