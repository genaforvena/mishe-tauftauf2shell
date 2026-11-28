#!/usr/bin/env bash
# W365: valgrind matrix for the UTF-8/ASCII encoding-tag boundary of
# String#casecmp?. Raw evidence is gitignored under
# lab/build/evidence/casemap-chain/w365/.
set -u
cd "$(dirname "$0")/../.." || exit 1
EVID=lab/build/evidence/casemap-chain/w365
DRIVER=lab/repro/ruby2shell-rung3-utf8-tag.rb
mkdir -p "$EVID"

BUILDS=(ruby-3.4.12-plain ruby-3.4.13-plain)
MODES=(latin_arg utf8_invalid utf8_valid usascii_arg ascii_arg)

for ver in "${BUILDS[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  [ -x "$rb" ] || { echo "missing $rb" >&2; exit 2; }
  for mode in "${MODES[@]}"; do
    for n in 27 43; do
      out="$EVID/vg-$ver-$mode-$n.txt"
      timeout 90 valgrind --error-limit=no "$rb" "$DRIVER" "$n" "$mode" >"$out" 2>&1
      rc=$?
      writes=$(grep -c 'Invalid write of size' "$out" || true)
      reads=$(grep -c 'Invalid read of size' "$out" || true)
      site=$(grep -m1 -o 'case_map [a-z0-9_/]*\.c:[0-9]*' "$out" || true)
      block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$out" || true)
      result=$(grep -m1 -o 'result=[^ ]*' "$out" || true)
      printf 'vg build=%s mode=%s N=%s rc=%s writes=%s reads=%s %s %s %s\n' \
        "$ver" "$mode" "$n" "$rc" "$writes" "$reads" "$site" "$block" "$result"
    done
  done
done

# W373: direct String#upcase tag matrix, odd N=21 vs clean N=20.
EVID373=lab/build/evidence/casemap-chain/w373
mkdir -p "$EVID373"
UPCASE_MODES=(upcase_latin upcase_utf8_invalid upcase_utf8_valid upcase_usascii upcase_ascii)

for ver in "${BUILDS[@]}"; do
  rb="lab/build/plain/$ver/bin/ruby"
  for mode in "${UPCASE_MODES[@]}"; do
    for n in 21 20; do
      out="$EVID373/vg-$ver-$mode-$n.txt"
      timeout 90 valgrind --error-limit=no "$rb" "$DRIVER" "$n" "$mode" >"$out" 2>&1
      rc=$?
      writes=$(grep -c 'Invalid write of size' "$out" || true)
      reads=$(grep -c 'Invalid read of size' "$out" || true)
      site=$(grep -m1 -o 'case_map [a-z0-9_/]*\.c:[0-9]*' "$out" || true)
      block=$(grep -m1 -o '0 bytes after a block of size [0-9]*' "$out" || true)
      result=$(grep -m1 -o 'result=[^ ]*' "$out" || true)
      printf 'vg373 build=%s mode=%s N=%s rc=%s writes=%s reads=%s %s %s %s\n' \
        "$ver" "$mode" "$n" "$rc" "$writes" "$reads" "$site" "$block" "$result"
    done
  done
done
