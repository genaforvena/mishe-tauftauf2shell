#!/usr/bin/env bash
# W337: 4-build consumer differential for the stale slice! tail.
# Arms: marshal_fixnum, marshal_string (coerced + nocoerce), unpackp.
# Evidence is gitignored under lab/build/evidence/slice-bang-consumer/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/slice-bang-consumer
mkdir -p "$EVID"
: >"$EVID/matrix.txt"

run() { # build tag arm coerce
  local build="$1" tag="$2" arm="$3" coerce="$4"
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/$build/bin/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 W337_ARM="$arm" W337_COERCE="$coerce" \
    timeout 15 "$rb" lab/repro/ruby2shell-slice-bang-consumer.rb \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  local rc=$?
  local asan kind result
  asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
  kind=$(grep -m1 -E 'ERROR: AddressSanitizer: [a-z-]+.*' "$EVID/$tag.err" || true)
  result=$(grep -m1 '^RESULT' "$EVID/$tag.out" || true)
  printf '%s tag=%s arm=%s coerce=%s rc=%s asan=%s %s %s\n' \
    "$build" "$tag" "$arm" "$coerce" "$rc" "$asan" "$kind" "${result:-NO_RESULT}" \
    | sed 's/  */ /g'
}

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  for arm in marshal_fixnum marshal_string unpackp; do
    run "$build" "$build-$arm" "$arm" 1
  done
  for arm in marshal_fixnum marshal_string; do
    run "$build" "$build-$arm-nocoerce" "$arm" 0
  done
done >"$EVID/matrix.txt"
cat "$EVID/matrix.txt"
