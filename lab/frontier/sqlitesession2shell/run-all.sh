#!/bin/sh
# Frontier runner: pinned SQLite 3.53.4 vs 3.54.0 Session changeset nCol
# differential. PASS counts are assertions, not rung 4 or rung 5 claims.
set -u
cd "$(dirname "$0")"
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s\n' "$1"; }
chk()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
mkdir -p runs

chk 'vulnerable pinned session source hash' \
  '[ "$(sha256sum src-vuln/sqlite-src-3530400/ext/session/sqlite3session.c | cut -d" " -f1)" = 403dfc4b8ef9a73f249e74e06f09314904199bc7cab56741f0caf1f43e3f7b66 ]'
chk 'fixed pinned session source hash' \
  '[ "$(sha256sum src-fixed/sqlite-src-3540000/ext/session/sqlite3session.c | cut -d" " -f1)" = 7e4675d27f20727de8472877d47a697d03d97ba9b21dd0dc3c597c095dbf8034 ]'
chk 'trigger fixture is the pinned 242-byte upstream blob' \
  '[ "$(sha256sum pins/changeset-trigger.bin | cut -d" " -f1)" = a5fd19bffb0cce234d4ec6b58b5977a2dbbe7ce9f17d3c54fe78e1d69ec81403 ] && [ "$(wc -c < pins/changeset-trigger.bin)" -eq 242 ]'
chk 'control fixture is its pinned 28-byte first block' \
  '[ "$(sha256sum pins/changeset-control.bin | cut -d" " -f1)" = 4831369a4fc52bf1e79d9b9c6c816cbe6d26ed0197589d996c85cd812a6471b2 ] && [ "$(wc -c < pins/changeset-control.bin)" -eq 28 ]'
chk 'upstream fix patch names the pinned commits' \
  'grep -Fq "64459c87cc702d600704fb77ee40ca1782398a52" pins/fix.patch && grep -Fq "FossilOrigin-Name: 3f57024aecea0f3b565ed823cf94b085031c481fd6323c1f2e4319a53500864f" pins/fix.patch'
chk 'upstream fix replaces name comparison with bNew' \
  'grep -Fq "sessionChangesetNext(pIter, 0, 0,&bNew)" pins/fix.patch && grep -Fq "+    if( bNew ){" pins/fix.patch'

# ASan differential. The 4-byte request is rounded to a 16-byte SQLite chunk:
# observed report is 12 bytes at 0 bytes past that 16-byte region.
for pin in vuln fixed; do
  for case in control trigger; do
    ./harness-$pin-asan $case > runs/$pin-asan-$case.out 2>&1; rc=$?
    printf 'CASE %s asan %s rc=%d\n' "$pin" "$case" "$rc"
    chk "$pin asan $case prints pinned version" \
      "grep -Fq 'version=' runs/$pin-asan-$case.out"
    chk "$pin asan $case prints fixture length" \
      "grep -Fq 'n-changeset=' runs/$pin-asan-$case.out"
    if [ "$pin" = vuln ] && [ "$case" = trigger ]; then
      chk 'vulnerable asan trigger faults' "[ \"$rc\" -ne 0 ]"
      chk 'vulnerable asan trigger heap-buffer-overflow' \
        'grep -Fq "ERROR: AddressSanitizer: heap-buffer-overflow" runs/vuln-asan-trigger.out'
      chk 'vulnerable asan trigger WRITE of size 12' \
        'grep -Fq "WRITE of size 12" runs/vuln-asan-trigger.out'
      chk 'vulnerable asan trigger 0 bytes after 16-byte region' \
        'grep -Fq "is located 0 bytes after 16-byte region" runs/vuln-asan-trigger.out'
      chk 'vulnerable asan trigger raw pinned amalgamation sink frame' \
        'grep -Fq "sessionUpdateFind src-vuln/sqlite-src-3530400/sqlite3.c:238155" runs/vuln-asan-trigger.out'
      chk 'vulnerable asan trigger reaches sqlite3changeset_apply' \
        'grep -Fq "sqlite3changeset_apply" runs/vuln-asan-trigger.out'
      chk 'vulnerable asan trigger allocation at pinned malloc line' \
        'grep -Fq "sessionUpdateFind src-vuln/sqlite-src-3530400/sqlite3.c:238148" runs/vuln-asan-trigger.out'
    else
      chk "$pin asan $case exits 0" "[ \"$rc\" -eq 0 ]"
      chk "$pin asan $case apply-rc=0" \
        "grep -Fq 'apply-rc=0' runs/$pin-asan-$case.out"
      chk "$pin asan $case ASan-clean" \
        "! grep -Fq 'AddressSanitizer' runs/$pin-asan-$case.out"
    fi
  done
done

chk 'vulnerable-vs-fixed differential: only vulnerable trigger faults' \
  'grep -Fq "AddressSanitizer" runs/vuln-asan-trigger.out && ! grep -Fq "AddressSanitizer" runs/fixed-asan-trigger.out'
chk 'safe control apply-rc=0 on both pins' \
  'grep -Fq "apply-rc=0" runs/vuln-asan-control.out && grep -Fq "apply-rc=0" runs/fixed-asan-control.out'

# Plain (non-ASan) builds: the vulnerable trigger deterministically faults
# (observed rc=139) while both controls and both fixed runs exit 0. The plain
# crash is an observation only: no chosen-byte readback or rung 4/5 claim.
for pin in vuln fixed; do
  for case in control trigger; do
    ./harness-$pin-plain $case > runs/$pin-plain-$case.out 2>&1; rc=$?
    printf 'CASE %s plain %s rc=%d\n' "$pin" "$case" "$rc"
    if [ "$pin" = vuln ] && [ "$case" = trigger ]; then
      chk 'vulnerable plain trigger faults' "[ \"$rc\" -ne 0 ]"
      chk 'vulnerable plain trigger has no sanitizer report' \
        "! grep -Fq 'AddressSanitizer' runs/$pin-plain-$case.out"
    else
      chk "$pin plain $case exits 0" "[ \"$rc\" -eq 0 ]"
      chk "$pin plain $case apply-rc=0" \
        "grep -Fq 'apply-rc=0' runs/$pin-plain-$case.out"
      chk "$pin plain $case has no sanitizer report" \
        "! grep -Fq 'AddressSanitizer' runs/$pin-plain-$case.out"
    fi
  done
done
chk 'plain vulnerable-vs-fixed trigger differential' \
  'grep -Fq "n-changeset=242" runs/vuln-plain-trigger.out && ! grep -Fq "apply-rc=0" runs/vuln-plain-trigger.out && grep -Fq "apply-rc=0" runs/fixed-plain-trigger.out'

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
