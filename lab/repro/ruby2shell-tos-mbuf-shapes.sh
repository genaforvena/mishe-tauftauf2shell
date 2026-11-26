#!/usr/bin/env bash
# Bounded falsifier for the GHSA-7whj-cfh7-xgm4 mbuf-pointer lane: try ASCII
# class shapes that might allocate a non-NULL CClassNode.mbuf before the
# chosen one-bit OR at regparse.c:4589, and observe whether any arm changes
# regex semantics instead of faulting. Plain 3.4.12 versus fixed 3.4.13,
# with vulnerable-ASCII V=0x41 and UTF-8 controls. Evidence is gitignored
# under lab/build/evidence/tos-steer/mbuf-shapes/.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/tos-steer/mbuf-shapes
mkdir -p "$EVID/gdb"
RB=lab/repro/ruby2shell-tos-mbuf-shapes.rb
P12=lab/build/plain/ruby-3.4.12-plain/bin/ruby
P13=lab/build/plain/ruby-3.4.13-plain/bin/ruby
SHAPES=(base neg_w neg_d word posix_neg charprop intersect negated nested \
        range two_vals ascii_range utf8)

: >"$EVID/summary.txt"
for shape in "${SHAPES[@]}"; do
  for code in 100 120 41; do
    for pair in "v12:$P12" "f13:$P13"; do
      tag=${pair%%:*}
      bin=${pair#*:}
      out="$EVID/plain-$tag-$shape-$code.out"
      TOS_CODE=$code TOS_SHAPE=$shape timeout 20 "$bin" "$RB" >"$out" 2>&1
      rc=$?
      fault=$(grep -m1 -oE 'Segmentation fault at 0x[0-9a-f]+' "$out" | awk '{print $NF}')
      result=$(grep -m1 -oE 'REGEXPERROR.*' "$out" || true)
      printf '%-12s %-4s %-4s rc=%-3s fault=%-18s %s\n' \
        "$shape" "$tag" "$code" "$rc" "${fault:--}" "$result" \
        | tee -a "$EVID/summary.txt"
    done
  done
done

# Debugger confirmation: was the OR hit at 4589, and was mbuf NULL there?
: >"$EVID/gdb/summary.txt"
for shape in "${SHAPES[@]}"; do
  out="$EVID/gdb/$shape.out"
  timeout 90 gdb -q -batch \
    -ex 'set environment TOS_CODE 100' \
    -ex "set environment TOS_SHAPE $shape" \
    -x lab/repro/ruby2shell-tos-mbuf-shapes.gdb --args "$P12" \
    >"$out" 2>&1
  hits=$(grep -c '^HIT' "$out")
  mbufs=$(grep -oE 'mbuf=\([^)]*\)|mbuf=0x[0-9a-f]+' "$out" | sort -u | tr '\n' ' ')
  printf '%-12s hits=%-2s mbuf=%s\n' "$shape" "$hits" "${mbufs:--}" \
    | tee -a "$EVID/gdb/summary.txt"
done
echo "summary: $EVID/summary.txt ; gdb: $EVID/gdb/summary.txt"
