#!/usr/bin/env bash
# Run the two adjacent-GHSA cases from ruby2shell-adjacent-ghsas.rb against a
# vulnerable and a fixed ASan Ruby, capturing output under lab/build/evidence/.
# Expected: vulnerable 3.4.12 double-free -> ASan heap-use-after-free rc=1;
# to-s -> Ruby [BUG] Segmentation fault rc=139. Fixed 3.4.13: RegexpError and
# the expected (?...) string, both rc=0.  Never leave the lab.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/adjacent-ghsas
mkdir -p "$EVID"
RUBY12=lab/build/ruby-3.4.12-asan/bin/ruby
RUBY13=lab/build/ruby-3.4.13-asan/bin/ruby
SCRIPT=lab/repro/ruby2shell-adjacent-ghsas.rb
for pair in "12:$RUBY12" "13:$RUBY13"; do
  ver=${pair%%:*}
  bin=${pair#*:}
  [ -x "$bin" ] || { echo "missing $bin"; continue; }
  for case in double-free to-s; do
    out="$EVID/3.4.$ver-$case.out"
    UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 timeout 60 \
      "$bin" "$SCRIPT" "$case" >"$out" 2>&1
    rc=$?
    echo "3.4.$ver $case rc=$rc $out"
    grep -m1 -iE 'AddressSanitizer: heap-use-after-free|SUMMARY: AddressSanitizer|Segmentation fault|REGEXPERROR|\(\?-mix:' "$out" || echo "  (no expected marker)"
  done
done
