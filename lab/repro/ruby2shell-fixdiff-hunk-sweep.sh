#!/usr/bin/env bash
# W347: four-build differential over the coercion-free hunk arms.
# Evidence is gitignored under lab/build/evidence/fixdiff-hunk-sweep/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/fixdiff-hunk-sweep
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
ARMS="embed-promote tmp-frozen-io subseq succ reverse split chomp scrub index-bounds"

run() { # build tag arm
  local build="$1" tag="$2" arm="$3"
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/$build/bin/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 timeout 90 "$rb" \
    lab/repro/ruby2shell-fixdiff-hunk-sweep.rb "$arm" \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  local rc=$?
  local asan kind result
  asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
  kind=$(grep -m1 -E 'SUMMARY: AddressSanitizer: [a-z-]+.*' "$EVID/$tag.err" || true)
  result=$(grep '^SWEEP' "$EVID/$tag.out" || true)
  printf '%s tag=%s arm=%s rc=%s asan=%s %s %s\n' \
    "$build" "$tag" "$arm" "$rc" "$asan" "$kind" "${result//$'\n'/ | }" \
    | sed 's/  */ /g'
}

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for arm in $ARMS; do
    run "$build" "$build-$arm" "$arm"
  done
done >"$EVID/matrix.txt"
cat "$EVID/matrix.txt"
