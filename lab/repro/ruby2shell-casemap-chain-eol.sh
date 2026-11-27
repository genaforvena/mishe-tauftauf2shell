#!/usr/bin/env bash
# W352: valgrind memcheck and per-buffer capa/used tracing for the EOL Ruby
# 3.2.11 branch. An ASan build of 3.2.11 is NOT usable on this host: both
# -fsanitize=address,undefined and address-only builds abort during their own
# bootstrap (builtin_binary.inc / miniprelude.c) in parse.y's
# add_delayed_token with an unrelated heap-use-after-free. Plain + valgrind
# + gdb therefore carry this lane. Evidence is gitignored under
# lab/build/evidence/casemap-chain/w352/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w352
mkdir -p "$EVID"
: >"$EVID/valgrind-matrix.txt"
: >"$EVID/gdb-matrix.txt"
RB=lab/build/plain/ruby-3.2.11-plain/bin/ruby
GDB=lab/repro/ruby2shell-casemap-chain-3.2.11.gdb
SHAPES="sb21 sb1041 sb2100 sbmix1041 u03901041 u03b01041 umix1041"
OPS="upcase fold"

[ -x "$RB" ] || { echo "missing $RB" >&2; exit 2; }
[ -f "$GDB" ] || { echo "missing $GDB" >&2; exit 2; }

for shape in $SHAPES; do
  for op in $OPS; do
    tag="$shape-$op"
    valgrind --error-limit=no --track-origins=no \
      --log-file="$EVID/$tag.valgrind" \
      "$RB" lab/repro/ruby2shell-casemap-chain.rb "$shape" "$op" \
      >"$EVID/$tag.out" 2>"$EVID/$tag.err"
    rc=$?
    invalid=$(grep -c 'Invalid write' "$EVID/$tag.valgrind" || true)
    first_write=$(grep -m1 'Invalid write of size' "$EVID/$tag.valgrind" || true)
    result=$(grep '^CHAIN ' "$EVID/$tag.out" || true)
    printf '%s rc=%s invalid_write=%s %s %s\n' \
      "$tag" "$rc" "$invalid" "$first_write" "$result" | sed 's/  */ /g'

    gdb -q -batch -x "$GDB" --args "$RB" \
      lab/repro/ruby2shell-casemap-chain.rb "$shape" "$op" \
      >"$EVID/gdb-$tag.log" 2>&1
    grc=$?
    buffers=$(grep -c '^ALLOC ' "$EVID/gdb-$tag.log" || true)
    capas=$(grep '^ALLOC ' "$EVID/gdb-$tag.log" | sed -n 's/.*capa=\([0-9]*\).*/\1/p' | paste -sd, -)
    used=$(grep '^USED ' "$EVID/gdb-$tag.log" | sed -n 's/.*used=\([0-9]*\).*/\1/p' | paste -sd, -)
    printf 'gdb-%s buffers=%s capas=%s used=%s rc=%s\n' \
      "$tag" "$buffers" "$capas" "$used" "$grc"
  done
done >"$EVID/matrix.txt"
cat "$EVID/matrix.txt"
