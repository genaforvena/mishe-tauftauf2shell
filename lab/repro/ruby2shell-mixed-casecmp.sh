#!/usr/bin/env bash
# W362: casecmp? one-byte overflow differential at the successor size LSB.
# Valgrind: N=27/43/59 x 3 vulnerable + 3 patched plain builds.
# Plain: bounded reps with churn to expose glibc diagnostics, plus a
# mismatch-input arm and an even-N=28 no-header-slot control.
# Raw evidence is gitignored under lab/build/evidence/casemap-chain/w362/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w362
DRIVER=lab/repro/ruby2shell-rung3-mixed-casecmp.rb
mkdir -p "$EVID/plain"

VULN=(ruby-3.4.12-plain ruby-3.3.13-plain ruby-4.0.9-plain)
FIXED=(ruby-3.4.13-plain ruby-3.3.14-plain ruby-4.0.10-plain)

if [ "${SKIP_VG:-0}" != 1 ]; then
for ver in "${VULN[@]}" "${FIXED[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for n in 27 43 59; do
    out="$EVID/vg-$ver-$n.txt"
    timeout 90 valgrind --error-limit=no "$rb" "$DRIVER" "$n" match >"$out" 2>&1
    rc=$?
    writes=$(grep -c 'Invalid write of size 1' "$out" || true)
    reads=$(grep -c 'Invalid read of size' "$out" || true)
    block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$out" || true)
    site=$(grep -m1 -o 'case_map [a-z0-9_/]*\.c:[0-9]*' "$out" || true)
    result=$(grep -m1 -o 'result=[a-z]*' "$out" || true)
    printf 'vg build=%s N=%s rc=%s writes=%s reads=%s %s %s %s\n' \
      "$ver" "$n" "$rc" "$writes" "$reads" "$block" "$site" "$result"
  done
done
fi

plain_arm() {
  ver=$1; n=$2; mode=$3; i=$4
  rb="lab/build/plain/$ver/bin/ruby"
  out="$EVID/plain/$ver-$n-$mode-$i.txt"
  timeout 25 "$rb" "$DRIVER" "$n" "$mode" churn >"$out" 2>&1
  rc=$?
  diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$out" || true)
  result=$(grep -m1 -o 'result=[a-z]*' "$out" || true)
  printf 'plain build=%s N=%s mode=%s i=%s rc=%s %s %s\n' "$ver" "$n" "$mode" "$i" "$rc" "$diag" "$result"
}

for ver in "${VULN[@]}"; do
  for n in 27 43 59; do
    for i in 1 2 3 4 5; do plain_arm "$ver" "$n" match "$i"; done
  done
  for i in 1 2 3 4 5; do plain_arm "$ver" 28 match "$i"; done
done
for ver in "${FIXED[@]}"; do
  for n in 27 43 59; do
    for i in 1 2; do plain_arm "$ver" "$n" match "$i"; done
  done
done
for i in 1 2 3 4 5; do plain_arm ruby-3.4.12-plain 27 mismatch "$i"; done
