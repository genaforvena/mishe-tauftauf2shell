#!/usr/bin/env bash
# W349/W350: log per-buffer rb_str_casemap capa/used for every chain shape on
# the affected plain builds (all have debug symbols). Branch builds 3.3.13 and
# 4.0.9 have shifted string.c lines, so each uses its own gdb script.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain
mkdir -p "$EVID"
: >"$EVID/gdb-matrix.txt"
SHAPES="sb21 sb1041 sb2100 sbmix1041 u03901041 u03b01041 umix1041"
OPS="upcase fold"
BUILDS="ruby-3.4.12-plain ruby-3.4.13-plain ruby-3.3.13-plain ruby-4.0.9-plain"

for build in $BUILDS; do
  RB="lab/build/plain/$build/bin/ruby"
  [ -x "$RB" ] || { echo "missing $RB" >&2; exit 2; }
  script=lab/repro/ruby2shell-casemap-chain.gdb
  case "$build" in
    ruby-3.4.13-plain) script=lab/repro/ruby2shell-casemap-chain-fixed.gdb ;;
    ruby-3.3.13-plain) script=lab/repro/ruby2shell-casemap-chain-3.3.13.gdb ;;
    ruby-4.0.9-plain) script=lab/repro/ruby2shell-casemap-chain-4.0.9.gdb ;;
  esac
  for shape in $SHAPES; do
    for op in $OPS; do
      tag="$build-$shape-$op"
      gdb -q -batch -x "$script" --args "$RB" \
        lab/repro/ruby2shell-casemap-chain.rb "$shape" "$op" \
        >"$EVID/gdb-$tag.log" 2>&1
      rc=$?
      buffers=$(grep -c '^ALLOC ' "$EVID/gdb-$tag.log" || true)
      writes=$(grep '^USED ' "$EVID/gdb-$tag.log" | sed -n 's/.*used=\([0-9]*\).*/\1/p' | paste -sd, -)
      capas=$(grep '^ALLOC ' "$EVID/gdb-$tag.log" | sed -n 's/.*capa=\([0-9]*\).*/\1/p' | paste -sd, -)
      printf '%s buffers=%s capas=%s used=%s rc=%s\n' \
        "$tag" "$buffers" "$capas" "$writes" "$rc"
    done
  done
done >"$EVID/gdb-matrix.txt"
cat "$EVID/gdb-matrix.txt"
