#!/usr/bin/env bash
# W356: mixed-parity write offset on the other glibc-field alignment.
# One leading 'a' then N x 0xDF with N = 35/51/67 (N == 3 mod 16) makes
# capa = N+21 even and the overflow offset R = N+45 == 0 (mod 16), i.e.
# the single fixed 0x53 byte lands at the other successor-chunk field
# than the N == 11 (mod 16) arms of W353/W354/W355.
# Runs valgrind on all six plain builds (three vulnerable, three patched)
# and fresh unsanitized processes with an even-N safe control.
# Raw evidence is gitignored under lab/build/evidence/casemap-chain/w356/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w356
MIXED=lab/repro/ruby2shell-rung3-mixed.rb
mkdir -p "$EVID/plain"

VULN=(ruby-3.4.12-plain ruby-3.3.13-plain ruby-4.0.9-plain)
FIXED=(ruby-3.4.13-plain ruby-3.3.14-plain ruby-4.0.10-plain)

for ver in "${VULN[@]}" "${FIXED[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for n in 35 51 67; do
    valgrind --error-limit=no "$rb" "$MIXED" "$n" >"$EVID/vg-$ver-$n.txt" 2>&1
    rc=$?
    writes=$(grep -c 'Invalid write of size 1' "$EVID/vg-$ver-$n.txt" || true)
    reads=$(grep -c 'Invalid read of size' "$EVID/vg-$ver-$n.txt" || true)
    block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$EVID/vg-$ver-$n.txt" || true)
    site=$(grep -m1 -o 'case_map [a-z0-9_/]*\.c:[0-9]*' "$EVID/vg-$ver-$n.txt" || true)
    printf 'vg build=%s N=%s rc=%s writes=%s reads=%s %s %s\n' "$ver" "$n" "$rc" "$writes" "$reads" "$block" "$site"
  done
done

for ver in "${VULN[@]}" "${FIXED[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  for n in 35 51 67 36; do
    for i in 1 2 3; do
      "$rb" "$MIXED" "$n" >"$EVID/plain/$ver-$n-$i.txt" 2>&1
      rc=$?
      diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$EVID/plain/$ver-$n-$i.txt" || true)
      printf 'plain build=%s N=%s i=%s rc=%s %s\n' "$ver" "$n" "$i" "$rc" "$diag"
    done
  done
done
