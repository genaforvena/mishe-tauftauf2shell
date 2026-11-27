#!/usr/bin/env bash
# W351: valgrind memcheck the named case-map chain shapes on the patched
# branch releases (3.3.14 and 4.0.10). Evidence is gitignored under
# lab/build/evidence/casemap-chain/w351/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w351
mkdir -p "$EVID"
: >"$EVID/valgrind-matrix.txt"
BUILDS="ruby-3.3.14-plain ruby-4.0.10-plain"
SHAPES="sb21 sb1041 sb2100 sbmix1041 u03901041 u03b01041 umix1041"
OPS="upcase fold"

run() { # build shape op
  local build="$1" shape="$2" op="$3" tag="$1-$2-$3"
  local rb="lab/build/plain/$build/bin/ruby"
  local rc invalid first_write result
  valgrind --error-limit=no --track-origins=no \
    --log-file="$EVID/$tag.valgrind" \
    "$rb" lab/repro/ruby2shell-casemap-chain.rb "$shape" "$op" \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  rc=$?
  invalid=$(grep -c 'Invalid write' "$EVID/$tag.valgrind" || true)
  first_write=$(grep -m1 'Invalid write of size' "$EVID/$tag.valgrind" || true)
  result=$(grep '^CHAIN ' "$EVID/$tag.out" || true)
  printf '%s rc=%s invalid_write=%s %s %s\n' \
    "$tag" "$rc" "$invalid" "$first_write" "$result" | sed 's/  */ /g'
}

for build in $BUILDS; do
  rb="lab/build/plain/$build/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for shape in $SHAPES; do
    for op in $OPS; do
      run "$build" "$shape" "$op"
    done
  done
done >"$EVID/valgrind-matrix.txt"
cat "$EVID/valgrind-matrix.txt"
