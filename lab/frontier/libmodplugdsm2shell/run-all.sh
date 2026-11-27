#!/bin/sh
# Frontier runner: pinned vulnerable vs fixed libmodplug DSM loader.
# PASS counts are assertions, not a claim of rung 4/5.
set -u
cd "$(dirname "$0")"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

mkdir -p runs vectors
python3 gen_dsm.py vectors/attack241.dsm 241 >/dev/null
python3 gen_dsm.py vectors/safe240.dsm 240 >/dev/null

chk 'pinned source checksums' \
  '(cd pins && sha256sum -c SHA256SUMS >/dev/null 2>&1) && sha256sum -c pins/SINK_SHA256.txt >/dev/null 2>&1'
chk 'vector sizes' \
  '[ "$(wc -c < vectors/attack241.dsm)" = 2156 ] && [ "$(wc -c < vectors/safe240.dsm)" = 2148 ]'

UBSAN_OPTIONS=print_stacktrace=1 ./harness-vuln-bounds vectors/attack241.dsm > runs/bounds-vuln-241.out 2>&1
chk 'vulnerable 241 PATT: UBSan array-bounds at raw load_dsm.cpp:138 (WORD[240])' \
  "grep -Fq \"load_dsm.cpp:138\" runs/bounds-vuln-241.out && grep -Fq \"index 240 out of bounds for type 'WORD[240]'\" runs/bounds-vuln-241.out"
chk 'vulnerable 241 PATT: UBSan array-bounds at raw load_dsm.cpp:139 (MODCOMMAND*[240])' \
  "grep -Fq \"load_dsm.cpp:139\" runs/bounds-vuln-241.out && grep -Fq \"index 240 out of bounds for type 'MODCOMMAND *[240]'\" runs/bounds-vuln-241.out"

./harness-vuln-bounds vectors/safe240.dsm > runs/bounds-vuln-240.out 2>&1
chk 'vulnerable 240 PATT control: no sanitizer finding' \
  '! grep -Fq "runtime error" runs/bounds-vuln-240.out'
chk 'vulnerable 240 PATT control: Order[] unchanged' \
  'grep -Fq "ORDER[0..7]=ffffffffffffffff" runs/bounds-vuln-240.out'

./harness-fixed-bounds vectors/attack241.dsm > runs/bounds-fixed-241.out 2>&1
chk 'fixed 241 PATT control: no sanitizer finding' \
  '! grep -Fq "runtime error" runs/bounds-fixed-241.out'
chk 'fixed 241 PATT control: Order[] unchanged' \
  'grep -Fq "ORDER[0..7]=ffffffffffffffff" runs/bounds-fixed-241.out'

./harness-vuln-plain vectors/attack241.dsm > runs/plain-vuln-241.out 2>&1
chk 'plain vulnerable 241 PATT: Order[] corrupted' \
  'grep -Fq "READDMS=1" runs/plain-vuln-241.out && ! grep -Fq "ORDER[0..7]=ffffffffffffffff" runs/plain-vuln-241.out'
./harness-vuln-plain vectors/safe240.dsm > runs/plain-vuln-240.out 2>&1
chk 'plain vulnerable 240 PATT: Order[] intact' \
  'grep -Fq "ORDER[0..7]=ffffffffffffffff" runs/plain-vuln-240.out'
./harness-fixed-plain vectors/attack241.dsm > runs/plain-fixed-241.out 2>&1
chk 'plain fixed 241 PATT: Order[] intact' \
  'grep -Fq "ORDER[0..7]=ffffffffffffffff" runs/plain-fixed-241.out'

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
