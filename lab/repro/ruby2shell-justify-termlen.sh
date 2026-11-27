#!/usr/bin/env bash
# W341: 4-build differential for the rb_str_justify stale-termlen write.
# Evidence is gitignored under lab/build/evidence/justify-termlen/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/justify-termlen
mkdir -p "$EVID"
: >"$EVID/matrix.txt"

run() { # build tag arm
  local build="$1" tag="$2" arm="$3"
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/$build/bin/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 timeout 60 "$rb" \
    lab/repro/ruby2shell-justify-termlen.rb "$arm" \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  local rc=$?
  local asan kind result
  asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
  kind=$(grep -m1 -E 'SUMMARY: AddressSanitizer: [a-z-]+.*' "$EVID/$tag.err" || true)
  result=$(grep -m1 '^RESULT' "$EVID/$tag.out" || true)
  printf '%s tag=%s arm=%s rc=%s asan=%s %s %s\n' \
    "$build" "$tag" "$arm" "$rc" "$asan" "$kind" "${result:-NO_RESULT}" \
    | sed 's/  */ /g'
}

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  run "$build" "$build-attack" attack
  run "$build" "$build-nomut" nomut
  run "$build" "$build-safe" safe
done >"$EVID/matrix.txt"
cat "$EVID/matrix.txt"
