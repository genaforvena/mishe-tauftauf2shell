#!/usr/bin/env bash
# W349: valgrind memcheck the named case-map chain shapes on the vulnerable
# plain build. Evidence is gitignored under lab/build/evidence/casemap-chain/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain
mkdir -p "$EVID"
: >"$EVID/matrix.txt"
RB=lab/build/plain/ruby-3.4.12-plain/bin/ruby
[ -x "$RB" ] || { echo "missing $RB" >&2; exit 2; }
SHAPES="sb21 sb1041 sb2100 sbmix1041 u03901041 u03b01041 umix1041"
OPS="upcase fold"

run() { # shape op
  local shape="$1" op="$2" tag="$shape-$op" rc invalid summary result
  valgrind --error-limit=no --track-origins=no \
    --log-file="$EVID/$tag.valgrind" \
    "$RB" lab/repro/ruby2shell-casemap-chain.rb "$shape" "$op" \
    >"$EVID/$tag.out" 2>"$EVID/$tag.err"
  rc=$?
  invalid=$(grep -c 'Invalid write' "$EVID/$tag.valgrind" || true)
  summary=$(grep -m1 -E 'definitely lost|Invalid write of size' "$EVID/$tag.valgrind" || true)
  result=$(grep '^CHAIN ' "$EVID/$tag.out" || true)
  printf '%s shape=%s op=%s rc=%s invalid_write=%s %s %s\n' \
    "$tag" "$shape" "$op" "$rc" "$invalid" "$summary" "$result" | sed 's/  */ /g'
}

for shape in $SHAPES; do
  for op in $OPS; do
    run "$shape" "$op"
  done
done >"$EVID/matrix.txt"
cat "$EVID/matrix.txt"
