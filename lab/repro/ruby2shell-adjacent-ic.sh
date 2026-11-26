#!/usr/bin/env bash
# Run the case-insensitive adjacent-lane cases against vulnerable 3.4.12 and
# fixed 3.4.13 ASan builds, capturing evidence under lab/build/evidence/.
# Expected: wpqw 3.4.12 ASan global-buffer-overflow in match_at (rc=1) with
# false matches before it; 3.4.13 correct results, rc=0. pvgc 3.4.12 false
# match, 3.4.13 no match, neither with an ASan report. Never leave the lab.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/adjacent-ic
mkdir -p "$EVID"
RUBY12=lab/build/ruby-3.4.12-asan/bin/ruby
RUBY13=lab/build/ruby-3.4.13-asan/bin/ruby
SCRIPT=lab/repro/ruby2shell-adjacent-ic.rb
for pair in "12:$RUBY12" "13:$RUBY13"; do
  ver=${pair%%:*}
  bin=${pair#*:}
  [ -x "$bin" ] || { echo "missing $bin"; continue; }
  for case in wpqw pvgc; do
    out="$EVID/3.4.$ver-$case.out"
    UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
      ASAN_OPTIONS=detect_leaks=0 timeout 60 \
      "$bin" "$SCRIPT" "$case" >"$out" 2>&1
    rc=$?
    echo "3.4.$ver $case rc=$rc $out"
    grep -m6 -E '^(ctrl|crafted|normal|oob|short)-|SUMMARY: AddressSanitizer|ERROR: AddressSanitizer' "$out" \
      || echo "  (no marker)"
  done
done
