#!/usr/bin/env bash
# open1722vss2shell canonical runner.
# Compiles the UNMODIFIED Vss.c and InlineExports.c from two pinned Open1722
# commits against a driver that exercises only the public VSS API. No socket,
# listener or live target is used. The vulnerable tag trusts the on-wire path
# prefix beyond the declared ACF length; the fix commit clamps it.
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

pin tar-v0.9.7 src/vuln.tar.gz da6b4636298a065de1d60f602cc80916331306a9dfd26b3aa8f01a6ffcb4867f
pin tar-714067b0 src/fixed.tar.gz 1fad12744011da2b149c2c46b2012c6be72f87acb2995df52040e7e392d29af3
pin fix-commit-patch src/714067b0.patch 888948c60a3a587e5028df2b86d1aa46507e2071bf66d53ec4d1b3c9fa3917fe
pin driver poc.c ec04c8a21a900c6f1ce208e2c2931dafb7c88dacdeed21d6fe6fc471a9609a67

rm -rf src/vuln src/fixed src/out
mkdir -p src/vuln src/fixed src/out evidence
tar -xzf src/vuln.tar.gz -C src/vuln --strip-components=1
tar -xzf src/fixed.tar.gz -C src/fixed --strip-components=1

V=src/vuln
F=src/fixed
VFILE=$V/src/avtp/acf/custom/Vss.c
FFILE=$F/src/avtp/acf/custom/Vss.c
pin vulnerable-Vss.c "$VFILE" 487900680d54911ff205a9639d693982c8536485b5d62d499dd9852d7e1f7249
pin fixed-Vss.c "$FFILE" 6f85ac224b55e83c85e167b714aae01164ccaf2207ecb54149b42be1941ce9b0

VSTART=$(grep -n '^uint16_t Avtp_Vss_CalcVssPathLength' "$VFILE" | cut -d: -f1)
FSTART=$(grep -n '^uint16_t Avtp_Vss_CalcVssPathLength' "$FFILE" | cut -d: -f1)
if [ "$VSTART" = 295 ] && [ "$FSTART" = 294 ]; then
    ok 'PIN CalcVssPathLength at Vss.c:295 (vuln) / :294 (fixed)'
else
    printf 'PIN_FAIL function starts %s/%s (expected 295/294)\n' "$VSTART" "$FSTART"
    exit 1
fi
if grep -q 'path_length = vss_load_be16(vss_path_ptr) + 2;' "$VFILE" && \
   grep -q 'AVTP_VSS_FIXED_HEADER_LEN + Avtp_Vss_CalcVssPathLength(pdu)' "$VFILE"; then
    ok 'PIN vulnerable raw prefix read and unchecked setter offset'
else bad 'vulnerable source markers'; fi
if grep -q 'uint32_t total_length = (uint32_t)vss_load_be16(vss_path_ptr) + 2U;' "$FFILE" && \
   grep -q 'if (vss_path_length == 0)' "$FFILE" && \
   grep -q 'if (total_length > available)' "$FFILE"; then
    ok 'PIN fixed clamp, overflow test and setter no-op guard'
else bad 'fixed source markers'; fi
if grep -q 'total_length > available' src/714067b0.patch && \
   grep -q 'vss_path_length == 0' src/714067b0.patch; then
    ok 'PIN fix patch carries both hunks'
else bad 'fix patch hunks'; fi

OUT=src/out
for CC in gcc clang; do
    $CC -std=c11 -O0 -g -fno-omit-frame-pointer -fsanitize=address \
        -I$V/include poc.c "$VFILE" $V/src/avtp/export/InlineExports.c \
        -o "$OUT/vuln-$CC-asan" || { bad "build vuln $CC asan"; continue; }
    $CC -std=c11 -O0 -g -fno-omit-frame-pointer -fsanitize=address \
        -I$F/include poc.c "$FFILE" $F/src/avtp/export/InlineExports.c \
        -o "$OUT/fixed-$CC-asan" || { bad "build fixed $CC asan"; continue; }
    $CC -std=c11 -O0 -g -fno-omit-frame-pointer \
        -I$V/include poc.c "$VFILE" $V/src/avtp/export/InlineExports.c \
        -o "$OUT/vuln-$CC-plain" || { bad "build vuln $CC plain"; continue; }
    $CC -std=c11 -O0 -g -fno-omit-frame-pointer \
        -I$F/include poc.c "$FFILE" $F/src/avtp/export/InlineExports.c \
        -o "$OUT/fixed-$CC-plain" || { bad "build fixed $CC plain"; continue; }
    ok "builds $CC (vuln/fixed asan + plain, real Vss.c)"
done

clean() {
    bin=$1; arg=$2; tag=$3; want=$4
    log="evidence/$tag.log"
    "$bin" "$arg" >"$log" 2>&1
    rc=$?
    if [ "$rc" -eq 0 ] && ! grep -q 'AddressSanitizer' "$log" && grep -q "$want" "$log"; then
        ok "$tag: clean rc=0 $want"
    else
        bad "$tag: expected clean rc=0 $want (rc=$rc)"
    fi
}

for CC in gcc clang; do
    log="evidence/vuln-$CC-asan-read-oob.log"
    "$OUT/vuln-$CC-asan" read_oob >"$log" 2>&1
    if grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$log" && \
       grep -q 'READ of size 2' "$log" && \
       grep -q '0 bytes after 12-byte region' "$log" && \
       grep -q 'Avtp_Vss_CalcVssPathLength .*Vss.c:307' "$log"; then
        ok "$CC ASan: heap READ-2 past 12-byte VSS header at real Vss.c:307"
    else bad "$CC ASan: expected heap READ-2 at Vss.c:307"; fi

    clean "$OUT/vuln-$CC-asan" adjacent "vuln-$CC-asan-adjacent" 'adjacent len=16708'
    clean "$OUT/vuln-$CC-asan" wrap "vuln-$CC-asan-wrap" 'wrap b12=ff b13=5a b20=00'
    clean "$OUT/vuln-$CC-asan" safe "vuln-$CC-asan-safe" 'safe b18=5a'

    clean "$OUT/fixed-$CC-asan" read_oob "fixed-$CC-asan-read-oob" 'read_oob len=0'
    clean "$OUT/fixed-$CC-asan" adjacent "fixed-$CC-asan-adjacent" 'adjacent len=0'
    clean "$OUT/fixed-$CC-asan" wrap "fixed-$CC-asan-wrap" 'wrap b12=ff b13=ff b20=00'
    clean "$OUT/fixed-$CC-asan" safe "fixed-$CC-asan-safe" 'safe b18=5a'

    clean "$OUT/vuln-$CC-plain" adjacent "vuln-$CC-plain-adjacent" 'adjacent len=16708'
    clean "$OUT/vuln-$CC-plain" wrap "vuln-$CC-plain-wrap" 'b12=ff b13=5a b20=00'
    clean "$OUT/fixed-$CC-plain" wrap "fixed-$CC-plain-wrap" 'b12=ff b13=ff b20=00'
done

printf 'RESULT PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
