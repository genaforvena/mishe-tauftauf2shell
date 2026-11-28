#!/usr/bin/env bash
# W368: sharp-s threshold and distinct-address test for both case_map folds.
# Arms a hardware watch on every rb_str_casemap to_end (one per fold buffer),
# sweeps operand lengths that straddle the one-byte-of-room condition, and
# keeps vulnerable/patched plus valgrind/plain controls.
# Raw evidence is gitignored under lab/build/evidence/casemap-chain/w368/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w368
GDB=lab/repro/ruby2shell-twofold-watch-all.gdb
DRIVER=lab/repro/ruby2shell-twofold.rb
mkdir -p "$EVID"

VULN=lab/build/plain/ruby-3.4.12-plain/bin/ruby
FIXED=lab/build/plain/ruby-3.4.13-plain/bin/ruby
[ -x "$VULN" ] && [ -x "$FIXED" ] || { echo "missing ruby builds" >&2; exit 2; }

report() {
  local out="$1" label="$2"
  local summary trap_lines late_lines
  summary=$(grep -m1 '^SUMMARY ' "$out" || true)
  trap_lines=$(grep -c '^TRAP ' "$out" || true)
  late_lines=$(grep -c '^LATE ' "$out" || true)
  printf '%s traps=%s late=%s %s\n' "$label" "$trap_lines" "$late_lines" "$summary"
}

PAIRS_V="17:17 19:19 20:20 21:21 22:22 23:23 17:21 21:17 20:23 23:20 27:43"
PAIRS_F="17:17 20:20 21:21 22:22 23:23 27:43"

for pair in $PAIRS_V; do
  n1=${pair%%:*}; n2=${pair##*:}
  out="$EVID/gdb-3.4.12-$n1-$n2.txt"
  R2S_N1=$n1 R2S_N2=$n2 timeout 60 gdb -q -batch -x "$GDB" "$VULN" >"$out" 2>&1
  rc=$?
  report "$out" "gdb build=3.4.12 n1=$n1 n2=$n2 rc=$rc"
done
for pair in $PAIRS_F; do
  n1=${pair%%:*}; n2=${pair##*:}
  out="$EVID/gdb-3.4.13-$n1-$n2.txt"
  R2S_N1=$n1 R2S_N2=$n2 timeout 60 gdb -q -batch -x "$GDB" "$FIXED" >"$out" 2>&1
  rc=$?
  report "$out" "gdb build=3.4.13 n1=$n1 n2=$n2 rc=$rc"
done

# Independent oracles and unmodified-runtime controls on the threshold pairs.
for pair in 17:17 19:19 20:20 21:21 22:22 23:23 21:22; do
  n1=${pair%%:*}; n2=${pair##*:}
  for ver in 3.4.12 3.4.13; do
    rb="lab/build/plain/ruby-$ver-plain/bin/ruby"
    out="$EVID/vg-$ver-$n1-$n2.txt"
    timeout 90 valgrind --error-limit=no "$rb" "$DRIVER" "$n1" "$n2" >"$out" 2>&1
    rc=$?
    writes=$(grep -c 'Invalid write of size 1' "$out" || true)
    reads=$(grep -c 'Invalid read of size 1' "$out" || true)
    blocks=$(grep -o '0 bytes after a block of size [0-9]*' "$out" | sort -u | tr '\n' ',')
    printf 'vg build=%s n1=%s n2=%s rc=%s writes=%s reads=%s blocks=%s\n' \
      "$ver" "$n1" "$n2" "$rc" "$writes" "$reads" "$blocks"
    for i in 1 2; do
      pout="$EVID/plain-$ver-$n1-$n2-$i.txt"
      timeout 20 "$rb" "$DRIVER" "$n1" "$n2" >"$pout" 2>&1
      prc=$?
      diag=$(grep -c -E 'malloc|free|corrupt|abort' "$pout" || true)
      printf 'plain build=%s n1=%s n2=%s i=%s rc=%s diag=%s %s\n' \
        "$ver" "$n1" "$n2" "$i" "$prc" "$diag" "$(grep -m1 '^n1=' "$pout" || true)"
    done
  done
done
