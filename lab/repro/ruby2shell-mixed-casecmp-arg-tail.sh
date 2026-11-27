#!/usr/bin/env bash
# W363 plain-matrix tail: arms not reached before the 600 s deadline of
# ruby2shell-mixed-casecmp-arg.sh (4.0.9 N=43/59/28, all patched arms,
# and the 3.4.12 mismatch arm). Uses the same driver and diagnostics.
set -u
cd "$(dirname "$0")/../.." || exit 1
ulimit -c 0
EVID=lab/build/evidence/casemap-chain/w363
DRIVER=lab/repro/ruby2shell-rung3-mixed-casecmp-arg.rb
mkdir -p "$EVID/plain"

plain_arm() {
  ver=$1; n=$2; mode=$3; i=$4
  rb="lab/build/plain/$ver/bin/ruby"
  out="$EVID/plain/$ver-$n-$mode-$i.txt"
  [ -s "$out" ] && return 0
  timeout 25 "$rb" "$DRIVER" "$n" "$mode" churn >"$out" 2>&1
  rc=$?
  diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$out" || true)
  result=$(grep -m1 -o 'result=[a-z]*' "$out" || true)
  printf 'plain build=%s N=%s mode=%s i=%s rc=%s %s %s\n' "$ver" "$n" "$mode" "$i" "$rc" "$diag" "$result"
}

for n in 43 59 28; do
  for i in 1 2 3 4 5; do plain_arm ruby-4.0.9-plain "$n" match "$i"; done
done
for ver in ruby-3.4.13-plain ruby-3.3.14-plain ruby-4.0.10-plain; do
  for n in 27 43 59; do
    for i in 1 2; do plain_arm "$ver" "$n" match "$i"; done
  done
done
for i in 1 2 3 4 5; do plain_arm ruby-3.4.12-plain 27 mismatch "$i"; done
