#!/usr/bin/env bash
# Run the UTF-8 case-fold OOB matrix against vulnerable 3.4.12 and fixed
# 3.4.13 ASan builds. Evidence is gitignored under lab/build/evidence/.
# Expected: affected sharp-s/sharp-cap/dotted-i abort with an ASan READ of
# size 1 in str_lower_case_match; ascii controls and every fixed case are
# clean. No network, no external target: this is an in-process harness.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/casefold-utf8
mkdir -p "$EVID"
SCRIPT=lab/repro/ruby2shell-casefold-utf8.rb
for pair in "12:lab/build/ruby-3.4.12-asan/bin/ruby" "13:lab/build/ruby-3.4.13-asan/bin/ruby"; do
  ver=${pair%%:*}
  bin=${pair#*:}
  [ -x "$bin" ] || { echo "missing $bin"; continue; }
  for name in sharp-s sharp-cap dotted-i ascii-match ascii-miss; do
    out="$EVID/3.4.$ver-$name.out"
    UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
      ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 timeout 60 \
      "$bin" "$SCRIPT" "$name" >"$out" 2>&1
    rc=$?
    hit=$(grep -c 'ERROR: AddressSanitizer' "$out" || true)
    echo "3.4.$ver $name rc=$rc asan=$hit $out"
    grep -m2 -E '^case=|SUMMARY: AddressSanitizer' "$out" || echo "  (no marker)"
  done
done
