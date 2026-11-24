#!/bin/sh
# c-icap CVE-2026-136126 replay. All hashes check pinned upstream bytes.
set -u
cd "$(dirname "$0")" || exit 1
mkdir -p evidence
PASS=0
FAIL=0
ok() { printf 'PASS %s\n' "$1"; PASS=$((PASS + 1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL + 1)); }
hashcheck() {
    a=$(sha256sum "$1" | cut -d' ' -f1)
    if [ "$a" = "$2" ]; then ok "hash $(basename "$1")"; else bad "hash $(basename "$1")"; fi
}

BAD=0
checkall() {
    hashcheck pinned/request_common.c b4988efe47003291ef8fe074a0d37a9504155fcef424940572299def762c37ad || BAD=1
    hashcheck pinned/header.c fa3fe4efceb985d5aa29cd9238be374490172b1d79f41ba0833710ab6b39219a || BAD=1
    hashcheck pinned/request.h e953e2f68a839f264255dc50d2b64af20ee48b22fa855e727099aaa2ba1e4619 || BAD=1
    hashcheck pinned/header.h 760e573b77139d62418827ed924e554bfb1e72aa5d13c9abbe7b66fd34e13fb3 || BAD=1
    hashcheck pinned/fix.patch 42e414fe70b07cbab0805143569119901d5243e3fc1e5b185d4152df3554b9de || BAD=1
    hashcheck pinned/process_encapsulated_vuln.inc 05b74ffd1d0abd30fd01b04873cb149006a0de66a1528f96e31cfccb4b45d174 || BAD=1
    hashcheck pinned/process_encapsulated_fixed.inc 17713a3bf1c067f6993bcf13dd1abfcbdc8545be0531f3c29115654bd0846d66 || BAD=1
    hashcheck pinned/destroy_vuln.inc a29d221d97fa4b7334d23e05154f910bf7eee0d5f0b50ee7670123be97aea18c || BAD=1
    hashcheck pinned/destroy_fixed.inc 8fb600c252f43d5962b4fad3a744a2fe57e3285b66c8d65f1159c41bb1b8964e || BAD=1
    hashcheck harness.c a1daab80114f2d09124b09d359bf6b32bd831659a3278e76beb466866728bdf4 || BAD=1
}
checkall

CFLAGS='-std=gnu11 -O0 -g -fno-omit-frame-pointer'
gcc $CFLAGS -fsanitize=address harness.c -o vuln-asan || exit 1
gcc $CFLAGS harness.c -o vuln-plain || exit 1
gcc $CFLAGS -fsanitize=address -DCICAP_FIXED harness.c -o fixed-asan || exit 1
gcc $CFLAGS -DCICAP_FIXED harness.c -o fixed-plain || exit 1

run() {
    log=$1
    shift
    "$@" > "evidence/$log.txt" 2>&1
    printf '%s\n' "$?" > "evidence/$log.rc"
    rc=$(cat "evidence/$log.rc")
}

run asan-vuln-attack ./vuln-asan vuln attack
rc=$(cat evidence/asan-vuln-attack.rc)
if [ "$rc" -ne 0 ] && grep -q 'AddressSanitizer: heap-use-after-free' evidence/asan-vuln-attack.txt \
   && grep -q 'destroy_encaps_entity' evidence/asan-vuln-attack.txt \
   && grep -q 'destroy_vuln.inc' evidence/asan-vuln-attack.txt; then
    ok asan-vuln-attack
else
    bad asan-vuln-attack
fi

run plain-vuln-attack-90 ./vuln-plain vuln attack
rc=$(cat evidence/plain-vuln-attack-90.rc)
if [ "$rc" -ne 0 ] && grep -q 'alias=1 trash0_type=2 trash0_start=90' evidence/plain-vuln-attack-90.txt; then
    ok plain-vuln-attack-90
else
    bad plain-vuln-attack-90
fi

run plain-vuln-attack-72 ./vuln-plain vuln attack72
rc=$(cat evidence/plain-vuln-attack-72.rc)
if [ "$rc" -ne 0 ] && grep -q 'alias=1 trash0_type=2 trash0_start=72' evidence/plain-vuln-attack-72.txt; then
    ok plain-vuln-attack-72
else
    bad plain-vuln-attack-72
fi

run asan-vuln-safe ./vuln-asan vuln safe
rc=$(cat evidence/asan-vuln-safe.rc)
if [ "$rc" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/asan-vuln-safe.txt \
   && grep -q 'entities\[5\]=(nil)' evidence/asan-vuln-safe.txt; then
    ok asan-vuln-safe
else
    bad asan-vuln-safe
fi

run plain-vuln-safe ./vuln-plain vuln safe
rc=$(cat evidence/plain-vuln-safe.rc)
if [ "$rc" -eq 0 ] && grep -q 'alias=0' evidence/plain-vuln-safe.txt && grep -q 'destroy done' evidence/plain-vuln-safe.txt; then
    ok plain-vuln-safe
else
    bad plain-vuln-safe
fi

run asan-fixed-attack ./fixed-asan fixed attack
rc=$(cat evidence/asan-fixed-attack.rc)
if [ "$rc" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/asan-fixed-attack.txt \
   && grep -q 'entities\[5\]=(nil)' evidence/asan-fixed-attack.txt; then
    ok asan-fixed-attack
else
    bad asan-fixed-attack
fi

run plain-fixed-attack ./fixed-plain fixed attack
rc=$(cat evidence/plain-fixed-attack.rc)
if [ "$rc" -eq 0 ] && grep -q 'alias=0' evidence/plain-fixed-attack.txt && grep -q 'destroy done' evidence/plain-fixed-attack.txt; then
    ok plain-fixed-attack
else
    bad plain-fixed-attack
fi

run asan-fixed-safe ./fixed-asan fixed safe
rc=$(cat evidence/asan-fixed-safe.rc)
if [ "$rc" -eq 0 ] && ! grep -q 'ERROR: AddressSanitizer' evidence/asan-fixed-safe.txt; then
    ok asan-fixed-safe
else
    bad asan-fixed-safe
fi

run plain-fixed-safe ./fixed-plain fixed safe
rc=$(cat evidence/plain-fixed-safe.rc)
if [ "$rc" -eq 0 ] && grep -q 'destroy done' evidence/plain-fixed-safe.txt; then
    ok plain-fixed-safe
else
    bad plain-fixed-safe
fi

printf 'TOTAL %s PASS / %s FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] && [ "$BAD" -eq 0 ]
