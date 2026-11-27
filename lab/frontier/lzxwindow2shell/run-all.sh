#!/bin/sh
# Frontier runner: pinned 7-Zip 26.05 vs 26.06 LZX window-desync differential.
# PASS counts are assertions, not a claim of rung 4 or rung 5.
set -u
cd "$(dirname "$0")"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
mkdir -p runs

chk 'vulnerable pinned decoder hash' \
  '[ "$(sha256sum src-vuln/7zip-26.05/CPP/7zip/Compress/LzxDecoder.cpp | cut -d" " -f1)" = 92844d4d58653c746439b79f146128bb8196aca1f9869e43810bffb4341fd5e6 ]'
chk 'fixed pinned decoder hash' \
  '[ "$(sha256sum src-fixed/7zip-26.06/CPP/7zip/Compress/LzxDecoder.cpp | cut -d" " -f1)" = 384826a8913fc80e17a6188ace7371e668cbfc250be1bb4b4b5deeef7152732e ]'
chk 'verbatim tag diff contains the two reset lines' \
  'grep -Fq "+      _pos = 0;" pins/fix.patch && grep -Fq "+      _overDict = false;" pins/fix.patch'
chk 'tag diff is one file, four added lines' \
  '[ "$(grep -c "^+" pins/fix.patch)" -eq 5 ]'

# Published geometry: 21-bit window advanced to 0x14A420, shrunk to 15 bits.
for pin in vuln fixed; do
  ./harness-$pin-asan 65 0x14A420 > runs/$pin-asan-pub.out 2>&1; rc=$?
  chk "$pin published phase1 advances pos" \
    'grep -Fq "PHASE1 set=0x0 decode=0x0 pos=1352736 winSize=2097152" runs/'"$pin"'-asan-pub.out'
  if [ "$pin" = vuln ]; then
    chk 'vulnerable published phase2 retains stale pos' \
      'grep -Fq "PHASE2 set=0x0 pos=1352736 winSize=32768" runs/vuln-asan-pub.out'
    chk 'vulnerable published write faults' "[ \"$rc\" -ne 0 ]"
    chk 'vulnerable published ASan report' \
      'grep -Fq "ERROR: AddressSanitizer" runs/vuln-asan-pub.out'
    chk 'vulnerable published raw pinned sink frame' \
      'grep -Fq "LzxDecoder.cpp:1396" runs/vuln-asan-pub.out'
  else
    chk 'fixed published phase2 resets pos' \
      'grep -Fq "PHASE2 set=0x0 pos=0 winSize=32768" runs/fixed-asan-pub.out'
    chk 'fixed published run exits 0' "[ \"$rc\" -eq 0 ]"
    chk 'fixed published run ASan clean' \
      '! grep -Fq "AddressSanitizer" runs/fixed-asan-pub.out'
    chk 'fixed published phase3 writes into new window' \
      'grep -Fq "PHASE3 decode=0x1 pos=4096 winSize=32768" runs/fixed-asan-pub.out'
  fi
done

# Near geometry: same stale-state transition, write lands in an ASan redzone.
for pin in vuln fixed; do
  ./harness-$pin-asan 65 0x9000 > runs/$pin-asan-near.out 2>&1; rc=$?
  chk "$pin near phase1 advances pos" \
    'grep -Fq "PHASE1 set=0x0 decode=0x0 pos=36864 winSize=2097152" runs/'"$pin"'-asan-near.out'
  if [ "$pin" = vuln ]; then
    chk 'vulnerable near run faults' "[ \"$rc\" -ne 0 ]"
    chk 'R3 ASan heap-buffer-overflow' \
      'grep -Fq "ERROR: AddressSanitizer: heap-buffer-overflow" runs/vuln-asan-near.out'
    chk 'R3 ASan WRITE of 4096' \
      'grep -Fq "WRITE of size 4096" runs/vuln-asan-near.out'
    chk 'R3 raw pinned sink frame' \
      'grep -Fq "LzxDecoder.cpp:1396" runs/vuln-asan-near.out'
    chk 'R3 write past 32800-byte window allocation' \
      'grep -Fq "after 32800-byte region" runs/vuln-asan-near.out'
  else
    chk 'fixed near phase2 resets pos' \
      'grep -Fq "PHASE2 set=0x0 pos=0 winSize=32768" runs/fixed-asan-near.out'
    chk 'fixed near run exits 0' "[ \"$rc\" -eq 0 ]"
    chk 'fixed near run ASan clean' \
      '! grep -Fq "AddressSanitizer" runs/fixed-asan-near.out'
  fi
done

# Plain-build negative: the far write lands in mapped heap, no full-program
# crash; chosen-byte readback through a real consumer is NOT claimed.
for pin in vuln fixed; do
  ./harness-$pin-plain 65 0x9000 > runs/$pin-plain-near.out 2>&1; rc=$?
  chk "$pin plain near run exits 0" "[ \"$rc\" -eq 0 ]"
done
chk 'vulnerable plain retained stale pos' \
  'grep -Fq "PHASE3 decode=0x1 pos=40960 winSize=32768" runs/vuln-plain-near.out'
chk 'fixed plain reset pos' \
  'grep -Fq "PHASE3 decode=0x1 pos=4096 winSize=32768" runs/fixed-plain-near.out'

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
