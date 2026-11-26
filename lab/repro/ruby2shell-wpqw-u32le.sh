#!/usr/bin/env bash
# Drive the UTF-32LE wpqw adjacent probes on vulnerable 3.4.12 and fixed
# 3.4.13 ASan builds. Evidence is gitignored under lab/build/evidence/.
# Each index/codepoint is a separate process: the OOB arm aborts under ASan.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/wpqw-u32le
mkdir -p "$EVID"
RUBY12=lab/build/ruby-3.4.12-asan/bin/ruby
RUBY13=lab/build/ruby-3.4.13-asan/bin/ruby
SCRIPT=lab/repro/ruby2shell-wpqw-u32le.rb
run() {
  ver=$1; bin=$2; shift 2
  tag=$1; shift
  out="$EVID/3.4.$ver-$tag.out"
  UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 \
    ASAN_OPTIONS=detect_leaks=0 timeout 30 \
    "$bin" "$SCRIPT" "$@" >"$out" 2>&1
  rc=$?
  marker=$(grep -E '^(steer|exact)' "$out" | tr '\n' ' ')
  asan=$(grep -m1 'SUMMARY: AddressSanitizer' "$out" || true)
  echo "3.4.$ver $tag rc=$rc $marker $asan"
}
for pair in "12:$RUBY12" "13:$RUBY13"; do
  ver=${pair%%:*}
  bin=${pair#*:}
  [ -x "$bin" ] || { echo "missing $bin"; continue; }
  for idx in 0 1 2 10 14 61 98; do
    run "$ver" "$bin" "steer-idx$idx" steer "$idx"
  done
  for cp in 0x03AB 0x103AB 0x203AB; do
    run "$ver" "$bin" "exact-$cp" exact "$cp"
  done
done
