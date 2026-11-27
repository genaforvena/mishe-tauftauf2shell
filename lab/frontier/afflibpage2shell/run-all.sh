#!/bin/sh
# Frontier runner: pinned vulnerable vs fixed AFFLIB af_get_page geometry.
# PASS counts are assertions, not a claim of rung 4 or rung 5.
set -u
cd "$(dirname "$0")"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1

mkdir -p runs
python3 gen_aff.py runs/vuln-crafted.aff 4096 100 > /dev/null
python3 gen_aff.py runs/fixed-crafted.aff 4096 100 > /dev/null
python3 gen_aff.py runs/safe.aff 512 4096 > /dev/null

chk 'pinned archives and fix patch' \
  '(cd pins && sha256sum -c SHA256SUMS >/dev/null 2>&1)'
chk 'harness and generator checksums' \
  'sha256sum -c HARNESS_SHA256.txt >/dev/null 2>&1'
chk 'crafted vector hash' \
  '[ "$(sha256sum runs/vuln-crafted.aff | cut -d" " -f1)" = f6fa12bd392e605d1f8974d87fabc0ff921d70be1f3b196d5493437187938e0e ]'
chk 'safe vector hash' \
  '[ "$(sha256sum runs/safe.aff | cut -d" " -f1)" = c44fa1365bb5a9ba0fcbd341285eaa9bb3d7d5e4fa89f9f07e93c6e4e82e5b71 ]'
chk 'vulnerable pinned sink source hash' \
  '[ "$(sha256sum src-vuln/lib/afflib_pages.cpp | cut -d" " -f1)" = 52f803606d850ac49df28491495eb999350abd873a5a0a53b4711776390b3499 ]'
chk 'fixed pinned sink source hash' \
  '[ "$(sha256sum src-fixed/lib/afflib_pages.cpp | cut -d" " -f1)" = 8363ba1c6c636f71dcdbbfefeef9e7d9310ef58ce59e229e117a99eb57f5da74 ]'
chk 'vulnerable fill loop is unbounded' \
  "grep -Fq 'for(size_t i = 0;i <= af->image_pagesize - af->image_sectorsize;' src-vuln/lib/afflib_pages.cpp"
chk 'fixed badblock fill has geometry guard' \
  "grep -Fq '&& af->image_sectorsize > 0 && af->image_pagesize >= af->image_sectorsize)' src-fixed/lib/afflib_pages.cpp"
chk 'fixed size validation rejects bad geometry' \
  "grep -Fq '(af->image_pagesize % af->image_sectorsize) != 0' src-fixed/lib/afflib_pages.cpp"

# R2 state: the crafted image supplies pagesize=100 with sectorsize=4096.
./harness-vuln ATTACK runs/vuln-crafted.aff 4096 100 100 \
  > runs/vuln-asan-attack.out 2>&1; rc=$?
chk 'vulnerable ASan run faults' "[ \"$rc\" -ne 0 ]"
chk 'R2 vulnerable geometry reaches fill' \
  'grep -Fq "LOADED pagesize=100 sectorsize=4096 badflag_set=1" runs/vuln-asan-attack.out'
chk 'R3 ASan heap-buffer-overflow' \
  'grep -Fq "ERROR: AddressSanitizer: heap-buffer-overflow" runs/vuln-asan-attack.out'
chk 'R3 ASan WRITE of 4096' \
  'grep -Fq "WRITE of size 4096" runs/vuln-asan-attack.out'
chk 'R3 raw pinned sink frame' \
  'grep -Fq "src-vuln/lib/afflib_pages.cpp:187" runs/vuln-asan-attack.out'
chk 'R3 zero bytes after exact 100-byte region' \
  'grep -Fq "0 bytes after 100-byte region" runs/vuln-asan-attack.out'

./harness-fixed ATTACK runs/fixed-crafted.aff 4096 100 100 \
  > runs/fixed-asan-attack.out 2>&1; rc=$?
chk 'fixed ASan run exits 0' "[ \"$rc\" -eq 0 ]"
chk 'fixed rejects invalid geometry' \
  'grep -Fq "LOADED pagesize=0 sectorsize=4096" runs/fixed-asan-attack.out'
chk 'fixed returns ENOENT without fill' \
  'grep -Fq "GETPAGE rc=-1 errno=2 bytes=100" runs/fixed-asan-attack.out'
chk 'fixed ASan output clean' \
  '! grep -Fq "AddressSanitizer" runs/fixed-asan-attack.out'

for spec in 'vuln vuln-crafted.aff' 'fixed fixed-crafted.aff'; do
    set -- $spec
    ./harness-$1 ATTACK runs/safe.aff 512 4096 4096 \
      > runs/$1-asan-safe.out 2>&1; rc=$?
    chk "$1 ASan safe-geometry control exits 0" "[ \"$rc\" -eq 0 ]"
    chk "$1 ASan safe-geometry control clean" \
      "! grep -Fq 'AddressSanitizer' runs/$1-asan-safe.out"
    chk "$1 ASan safe control reads page" \
      'grep -Fq "GETPAGE rc=0 errno=2 bytes=4096 first=42" runs/'"$1"'-asan-safe.out'
done

# Plain-build negative: the underflow loop keeps writing, so no chosen-byte
# readback is reached. Preserved as a negative, not a rung-4 claim.
./harness-plain-vuln CANARY runs/vuln-crafted.aff 4096 100 100 \
  > runs/vuln-plain-chosen.out 2>&1; rc=$?
chk 'vulnerable plain underflow loop faults before readback' \
  "[ \"$rc\" -ne 0 ]"
chk 'vulnerable plain produced no chosen-byte readback' \
  '! grep -Fq "CANARY first=" runs/vuln-plain-chosen.out'

./harness-plain-fixed CANARY runs/fixed-crafted.aff 4096 100 100 \
  > runs/fixed-plain-chosen.out 2>&1; rc=$?
chk 'fixed plain run exits 0' "[ \"$rc\" -eq 0 ]"
chk 'fixed plain leaves canary untouched' \
  'grep -Fq "CANARY first=0 last=0 count=0 at10=cc at64=cc at128=cc at256=cc" runs/fixed-plain-chosen.out'

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
