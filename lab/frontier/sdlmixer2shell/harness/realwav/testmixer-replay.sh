#!/bin/sh
# Replay the pinned tarball's UNMODIFIED test/testmixer.c with a crafted WAV.
# The only lab adaptation is testmixer-headless.c, which masks SDL_INIT_VIDEO
# because the committed SDL3 3.4.0 build has no video backend. No SDL_mixer
# source is changed. Requires the built deps/ trees from REALWAV.md.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
L=$(CDPATH= cd -- "$HERE/../.." && pwd)
D="$L/deps"
E="$HERE/evidence"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

command -v clang >/dev/null 2>&1 || { echo "clang missing"; exit 2; }
for f in "$D/mixer-vuln-asan-build/libSDL3_mixer.a" \
         "$D/mixer-fixed-asan-build/libSDL3_mixer.a" \
         "$D/SDL_mixer-vuln-src/test/testmixer.c" \
         "$D/SDL_mixer-fixed-src/test/testmixer.c"; do
    test -f "$f" || { echo "missing $f"; exit 2; }
done

SDLINC="-I$D/SDL-release-3.4.0/include -I$D/SDL3-3.4.0-build/include-revision"
COMMON="-g -O0 -fno-omit-frame-pointer -fsanitize=address"
CLANGLOG="$TMP/build.log"

# Build the headless shim separately: renaming SDL_Init in that translation
# unit would recurse into itself.
clang $COMMON $SDLINC -c "$HERE/testmixer-headless.c" -o "$TMP/headless.o" >>"$CLANGLOG" 2>&1

build() {
    tree=$1; out=$2
    clang $COMMON -DSDL_Init=testmixer_headless_Init \
        "-I$D/SDL_mixer-$tree-src/include" $SDLINC \
        "$D/SDL_mixer-$tree-src/test/testmixer.c" "$TMP/headless.o" \
        "$D/mixer-$tree-asan-build/libSDL3_mixer.a" \
        -L"$D/SDL3-3.4.0-build" -lSDL3 -Wl,-rpath,"$D/SDL3-3.4.0-build" \
        -lm -lpthread -ldl -o "$E/$out" >>"$CLANGLOG" 2>&1
}
build vuln testmixer-vuln-asan
build fixed testmixer-fixed-asan
cp "$CLANGLOG" "$E/testmixer-build.log"

export ASAN_SYMBOLIZER_PATH=${ASAN_SYMBOLIZER_PATH:-/usr/lib/llvm-18/bin/llvm-symbolizer}
export ASAN_OPTIONS=${ASAN_OPTIONS:-detect_leaks=0:abort_on_error=0}
export SDL_AUDIO_DRIVER=dummy
export MIX_DECODERS=3

pass=0; fail=0
check() {
    name=$1; want=$2
    ok=1
    grep -Fq "$want" "$E/$name.out" || ok=0
    actual=$(cat "$E/$name.rc")
    if [ "$actual" != "$3" ]; then ok=0; fi
    if [ "$ok" = 1 ]; then pass=$((pass+1)); echo "PASS $name rc=$actual"; else
        fail=$((fail+1)); echo "FAIL $name rc=$actual (wanted $3, marker '$want')";
    fi
}

run() {
    name=$1; bin=$2; wav=$3
    rc=0
    (cd "$E" && timeout 5s "./$bin" "$wav") >"$E/$name.out" 2>&1 || rc=$?
    printf '%s\n' "$rc" >"$E/$name.rc"
}

run testmixer-vuln-alaw256 testmixer-vuln-asan alaw256.wav
run testmixer-vuln-ulaw256 testmixer-vuln-asan ulaw256.wav
run testmixer-vuln-alaw8 testmixer-vuln-asan alaw8.wav
run testmixer-fixed-alaw256 testmixer-fixed-asan alaw256.wav

MARK='decoder_wav.c:759:16 in FetchXLaw'
check testmixer-vuln-alaw256 "$MARK" 1
check testmixer-vuln-ulaw256 "$MARK" 1
check testmixer-vuln-alaw8 'SDL_mixer.metadata.duration_frames' 0
check testmixer-fixed-alaw256 'SDL_mixer.metadata.duration_frames' 0

# Controls must not carry a sanitizer report.
for name in testmixer-vuln-alaw8 testmixer-fixed-alaw256; do
    if grep -Fq 'ERROR: AddressSanitizer' "$E/$name.out"; then
        echo "FAIL $name unexpected ASan"; fail=$((fail+1));
    else
        echo "PASS $name clean"; pass=$((pass+1));
    fi
done

echo "PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ]
