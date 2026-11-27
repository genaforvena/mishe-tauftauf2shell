#!/usr/bin/env bash
# W367: two-fold write independence for String#casecmp? (CVE-2026-132825).
# Each operand carries its own sharp-s count, so str_casecmp_p folds both and
# each ISO-8859-1 case_map call can write one byte past its own buffer.
# Raw evidence is gitignored under lab/build/evidence/casemap-chain/w367/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w367
DRIVER=lab/repro/ruby2shell-twofold.rb
mkdir -p "$EVID"

BUILDS=(ruby-3.4.12-plain ruby-3.4.13-plain)
NS=(27 43 59)

for ver in "${BUILDS[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for n1 in "${NS[@]}"; do
    for n2 in "${NS[@]}"; do
      out="$EVID/vg-$ver-$n1-$n2.txt"
      timeout 90 valgrind --error-limit=no "$rb" "$DRIVER" "$n1" "$n2" >"$out" 2>&1
      rc=$?
      writes=$(grep -c 'Invalid write of size 1' "$out" || true)
      reads=$(grep -c 'Invalid read of size 1' "$out" || true)
      blocks=$(grep -o '0 bytes after a block of size [0-9]*' "$out" | sort -u | tr '\n' ',')
      result=$(grep -m1 -o 'result=[^ ]*' "$out" || true)
      printf 'vg build=%s n1=%s n2=%s rc=%s writes=%s reads=%s blocks=%s %s\n' \
        "$ver" "$n1" "$n2" "$rc" "$writes" "$reads" "$blocks" "$result"
      for i in 1 2 3; do
        pout="$EVID/plain-$ver-$n1-$n2-$i.txt"
        timeout 20 "$rb" "$DRIVER" "$n1" "$n2" >"$pout" 2>&1
        prc=$?
        diag=$(grep -c -E 'malloc|free|corrupt|abort' "$pout" || true)
        printf 'plain build=%s n1=%s n2=%s i=%s rc=%s diag=%s %s\n' \
          "$ver" "$n1" "$n2" "$i" "$prc" "$diag" "$(grep -m1 '^n1=' "$pout" || true)"
      done
    done
  done
done
