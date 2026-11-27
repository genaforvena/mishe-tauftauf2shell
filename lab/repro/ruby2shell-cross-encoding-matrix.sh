#!/usr/bin/env bash
# W364: cross-encoding gate matrix for String#casecmp?. Six plain builds,
# two vulnerable order arms at N=27/43/59, two negative arms and one both-Latin
# control at N=27, plus bounded fresh-plain reps. Raw evidence is gitignored
# under lab/build/evidence/casemap-chain/w364/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w364
DRIVER=lab/repro/ruby2shell-rung3-cross-encoding.rb
mkdir -p "$EVID/plain"

VULN=(ruby-3.4.12-plain ruby-3.3.13-plain ruby-4.0.9-plain)
FIXED=(ruby-3.4.13-plain ruby-3.3.14-plain ruby-4.0.10-plain)
POS=(b_recv_l_arg l_recv_b_arg)
NEG=(both_b b_non7_l_arg both_l)

for ver in "${VULN[@]}" "${FIXED[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for mode in "${POS[@]}"; do
    for n in 27 43 59; do
      out="$EVID/vg-$ver-$mode-$n.txt"
      timeout 90 valgrind --error-limit=no "$rb" "$DRIVER" "$n" "$mode" >"$out" 2>&1
      rc=$?
      writes=$(grep -c 'Invalid write of size 1' "$out" || true)
      reads=$(grep -c 'Invalid read of size' "$out" || true)
      block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$out" || true)
      site=$(grep -m1 -o 'case_map [a-z0-9_/]*\.c:[0-9]*' "$out" || true)
      result=$(grep -m1 -o 'result=[a-z]*' "$out" || true)
      printf 'vg build=%s mode=%s N=%s rc=%s writes=%s reads=%s %s %s %s\n' \
        "$ver" "$mode" "$n" "$rc" "$writes" "$reads" "$block" "$site" "$result"
    done
  done
  for mode in "${NEG[@]}"; do
    out="$EVID/vg-$ver-$mode-27.txt"
    timeout 90 valgrind --error-limit=no "$rb" "$DRIVER" 27 "$mode" >"$out" 2>&1
    rc=$?
    writes=$(grep -c 'Invalid write of size 1' "$out" || true)
    reads=$(grep -c 'Invalid read of size' "$out" || true)
    result=$(grep -m1 -o 'result=[a-z]*' "$out" || true)
    printf 'vg build=%s mode=%s N=27 rc=%s writes=%s reads=%s %s\n' \
      "$ver" "$mode" "$rc" "$writes" "$reads" "$result"
  done
done

plain_arm() {
  ver=$1; mode=$2; n=$3; i=$4
  rb="lab/build/plain/$ver/bin/ruby"
  out="$EVID/plain/$ver-$mode-$n-$i.txt"
  timeout 25 "$rb" "$DRIVER" "$n" "$mode" churn >"$out" 2>&1
  rc=$?
  diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$out" || true)
  result=$(grep -m1 -o 'result=[a-z]*' "$out" || true)
  printf 'plain build=%s mode=%s N=%s i=%s rc=%s %s %s\n' \
    "$ver" "$mode" "$n" "$i" "$rc" "$diag" "$result"
}

for ver in "${VULN[@]}"; do
  for mode in "${POS[@]}"; do
    for i in 1 2 3 4 5; do plain_arm "$ver" "$mode" 27 "$i"; done
  done
  for mode in "${NEG[@]}"; do plain_arm "$ver" "$mode" 27 1; done
done
for ver in "${FIXED[@]}"; do
  for mode in "${POS[@]}"; do plain_arm "$ver" "$mode" 27 1; done
done
