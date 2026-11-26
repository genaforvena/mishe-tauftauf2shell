#!/usr/bin/env bash
# Drive the wpqw chosen-byte steering probe on vulnerable 3.4.12 and fixed
# 3.4.13, writing evidence under lab/build/evidence/ (gitignored). Each index
# is a separate process: high indices can crash during opcode dispatch.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/wpqw-steer
mkdir -p "$EVID"
RUBY12=lab/build/ruby-3.4.12-asan/bin/ruby
RUBY13=lab/build/ruby-3.4.13-asan/bin/ruby
SCRIPT=lab/repro/ruby2shell-wpqw-steer.rb
for pair in "12:$RUBY12" "13:$RUBY13"; do
  ver=${pair%%:*}
  bin=${pair#*:}
  [ -x "$bin" ] || { echo "missing $bin"; continue; }
  for idx in 0 1 2 10 14 61 98; do
    out="$EVID/3.4.$ver-idx$idx.out"
    UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
      ASAN_OPTIONS=detect_leaks=0 timeout 30 \
      "$bin" "$SCRIPT" "$idx" >"$out" 2>&1
    rc=$?
    marker=$(grep -m1 '^idx=' "$out" || echo '(none)')
    echo "3.4.$ver idx=$idx rc=$rc $marker"
  done
done
