#!/bin/bash
# One-command replay of the ctranslate22shell rung-3/rung-4-PARTIAL evidence.
# Offline; run from anywhere: bash lab/frontier/ctranslate22shell/run-witness.sh
# Prints "WITNESS REPLAY PASS" only if every staged and real-source control holds.
set -u
cd "$(dirname "$0")"
fail=0
ok() { echo "PASS $1"; }
no() { echo "FAIL $1"; fail=$((fail+1)); }
need() { # need FILE PATTERN LABEL
  if grep -q "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
need_not() {
  if grep -q "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}

echo "== staged pin harness (16 PASS / 0 FAIL expected)"
if bash harness/run-all.sh > /tmp/ct2-staged-replay.log 2>&1; then
  ok "staged harness $(tail -1 /tmp/ct2-staged-replay.log)"
else
  no "staged harness $(tail -1 /tmp/ct2-staged-replay.log)"
fi

echo "== real-source build (verbatim v4.8.0 model.cc + fixed d9b991e control)"
if sh realbuild/build.sh > /tmp/ct2-real-build.log 2>&1; then
  ok "real-source build"
else
  no "real-source build"
fi
need /tmp/ct2-real-build.log '05ab59bb4413df14d36fbbb0d82ff6ce6fe0bee72245245f8ecec773d4cc2c65' 'vulnerable model.cc sha256'
need /tmp/ct2-real-build.log '5dcc3f1daa0de260c068b4645728a28305b27393f9461e650f45c8db89c707b7' 'fixed model.cc sha256'

echo "== real-consumer controls"
R=realbuild/evidence
need $R/real-asan-17.out 'heap-buffer-overflow' 'ASan n=17 overflow'
need $R/real-asan-17.out 'WRITE of size 17' 'ASan n=17 WRITE of size 17'
need $R/real-asan-17.out 'src/models/model.cc:657' 'ASan n=17 write stack at model.cc:657'
need $R/real-asan-48.out 'WRITE of size 48' 'ASan n=48 WRITE of size 48'
need $R/real-asan-16.out 'victim\[0:16\]=VVVVVVVVVVVVVVVV' 'ASan n=16 safe clean'
need_not $R/real-asan-16.out 'ERROR: AddressSanitizer' 'ASan n=16 no report'
need $R/fixed-asan-17.out 'invalid payload size' 'fixed pin rejects n=17'
need_not $R/fixed-asan-17.out 'ERROR: AddressSanitizer' 'fixed pin no ASan report'
need $R/plain-16.out 'victim\[0:16\]=VVVVVVVVVVVVVVVV' 'plain n=16 chosen bytes'
need $R/plain-48.out 'malloc(): corrupted top size' 'plain n=48 heap metadata corruption'

echo "== verdict"
if [ "$fail" -eq 0 ]; then echo "WITNESS REPLAY PASS"; else echo "WITNESS REPLAY FAIL ($fail)"; fi
exit "$fail"
