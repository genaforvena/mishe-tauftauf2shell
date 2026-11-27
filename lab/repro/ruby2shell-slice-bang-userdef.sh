#!/usr/bin/env bash
# W339: 4-build stock-_load dispatch differential for the stale slice! tail.
# Arms: coerced (stale class name + nested payload) and integer-index control.
# Evidence is gitignored under lab/build/evidence/slice-bang-userdef/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/slice-bang-userdef
mkdir -p "$EVID"
: >"$EVID/matrix.txt"

run() { # build tag coerce
  local build="$1" tag="$2" coerce="$3"
  local rb
  case "$build" in
    *-plain) rb="lab/build/plain/$build/bin/ruby" ;;
    *) rb="lab/build/$build/bin/ruby" ;;
  esac
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ASAN_OPTIONS=detect_leaks=0 W339_COERCE="$coerce" \
    timeout 20 "$rb" lab/repro/ruby2shell-slice-bang-userdef.rb \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  local rc=$?
  local asan kind result
  asan=$(grep -c 'ERROR: AddressSanitizer' "$EVID/$tag.err" || true)
  kind=$(grep -m1 -E 'ERROR: AddressSanitizer: [a-z-]+.*' "$EVID/$tag.err" || true)
  result=$(grep -m1 '^RESULT' "$EVID/$tag.out" || true)
  printf '%s tag=%s coerce=%s rc=%s asan=%s %s %s\n' \
    "$build" "$tag" "$coerce" "$rc" "$asan" "$kind" "${result:-NO_RESULT}" \
    | sed 's/  */ /g'
}

for build in ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.4.12-asan ruby-3.4.13-asan; do
  run "$build" "$build-userdef" 1
  run "$build" "$build-nocoerce" 0
done >"$EVID/matrix.txt"
cat "$EVID/matrix.txt"
