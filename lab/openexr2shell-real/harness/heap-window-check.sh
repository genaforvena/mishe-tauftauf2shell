#!/bin/sh
# W185: one-command replay of two bounded negatives.
#  (1) In the flat harness the exr_decode_pipeline_t is STACK-resident: the
#      "live pointers inside the range" of W171 are pointer VALUES, not
#      pointer fields the W184 copy could steer. The two scratch pointers
#      are unchanged after the 128-byte chosen-byte copy.
#  (2) In UNMODIFIED exrcheck -c the survivable W184 copy sees zero code or
#      rodata pointers in [dst,dst+128); the process exits with a clean
#      "bad" (rc 1), not a chosen-address fault.
# No wire, pointer control, command or marker is claimed.
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
POC=work-mixed/poc_mixed_full_3c.exr
bin-vuln-plain/gen_baseline_deep_mixed "$BASE" >/dev/null
python3 cases/make_poc_mixed_full.py "$BASE" "$POC" 64 0x3c 256 >/dev/null
test "$(sha256sum "$BASE" | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04
test "$(sha256sum "$POC" | cut -d' ' -f1)" = \
    1fafb97255ad2178d8d68a1dec703f89b08aba2ac5f647658f3cd9187e6c8ba0

gdb -q -batch -x harness/pointer-fields.cmd \
    bin-vuln-plain/flat_harness 2>&1 \
    | grep -E '^(COPY2|FIELD|AFTER)' > evidence/w185-pointer-fields.out
grep -Fqx 'COPY2 dst_off=256 n=128' evidence/w185-pointer-fields.out
grep -Fqx 'FIELD scratch_buffer_1 stack=1 in_copy_window=0' evidence/w185-pointer-fields.out
grep -Fqx 'FIELD scratch_buffer_2 stack=1 in_copy_window=0' evidence/w185-pointer-fields.out
grep -Fqx 'AFTER scratch_buffer_1 unchanged=1' evidence/w185-pointer-fields.out
grep -Fqx 'AFTER scratch_buffer_2 unchanged=1' evidence/w185-pointer-fields.out

gdb -q -batch -x harness/heap-window.cmd \
    build-vuln-plain/bin/exrcheck 2>&1 \
    | grep -E '^(COPY2|PTR-|HEAP-)' > evidence/w185-heap-window.out
grep -Fqx 'COPY2 dst_off=256 n=128' evidence/w185-heap-window.out
grep -Fqx 'PTR-HITS total=0' evidence/w185-heap-window.out
grep -Fqx 'HEAP-VALUES total=3' evidence/w185-heap-window.out

build-vuln-plain/bin/exrcheck -c "$BASE" > evidence/w185-baseline.out 2>&1
build-vuln-plain/bin/exrcheck -c "$POC" > evidence/w185-poc.out 2>&1 || test $? -eq 1
build-fixed-plain/bin/exrcheck -c "$POC" > evidence/w185-fixed.out 2>&1 || test $? -eq 1
grep -Fq 'baseline_deep_mixed.exr OK' evidence/w185-baseline.out
grep -Fq 'poc_mixed_full_3c.exr bad' evidence/w185-poc.out
grep -Fq 'poc_mixed_full_3c.exr bad' evidence/w185-fixed.out
bin-fixed-asan/guarded_harness "$POC" 2>&1 \
    | grep -E '^(DECODE|GUARD-TOTAL)' > evidence/w185-fixed-guard.out
grep -Fqx 'DECODE rv=23 EXR_ERR_CORRUPT_CHUNK' evidence/w185-fixed-guard.out
grep -Fqx 'GUARD-TOTAL post-decode changed=0' evidence/w185-fixed-guard.out

printf 'RESULT PASS\n'
sha256sum evidence/w185-*.out
