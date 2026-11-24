#!/bin/sh
# Build real SDL_mixer 3.2.4 static libs with the AIFF decoder enabled.
# Vulnerable = pinned release-3.2.4; fixed = same tree with the 3448684
# one-line fix applied to src/decoder_aiff.c only (the WAV fix is irrelevant
# to this lane). No network access: all sources/provisioned builds are local.
set -eu
L=$(cd "$(dirname "$0")/../.." && pwd)
D="$L/deps"
SDL3_BUILD="$D/SDL3-3.4.0-build"

# Build the fixed tree from the pinned vulnerable tree plus the committed
# one-line fixed source, so a clean git archive can reproduce this lane.
if [ ! -d "$D/SDL_mixer-aiff-fixed-src" ]; then
    cp -a "$D/SDL_mixer-vuln-src" "$D/SDL_mixer-aiff-fixed-src"
fi
cp "$L/src/decoder_aiff.c.fixed" "$D/SDL_mixer-aiff-fixed-src/src/decoder_aiff.c"

build_mixer() {
    src="$1"; bld="$2"; cflags="$3"; lflags="$4"
    cmake -S "$src" -B "$bld" -G Ninja \
        -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="$cflags" \
        -DCMAKE_EXE_LINKER_FLAGS="$lflags" \
        -DCMAKE_SHARED_LINKER_FLAGS="$lflags" \
        -DSDL3_DIR="$SDL3_BUILD" \
        -DBUILD_SHARED_LIBS=OFF -DSDLMIXER_VENDORED=OFF -DSDLMIXER_INSTALL=OFF \
        -DSDLMIXER_TESTS=OFF -DSDLMIXER_EXAMPLES=OFF -DSDLMIXER_WERROR=OFF \
        -DSDLMIXER_WAVE=OFF -DSDLMIXER_AIFF=ON -DSDLMIXER_VOC=OFF -DSDLMIXER_AU=OFF \
        -DSDLMIXER_FLAC=OFF -DSDLMIXER_GME=OFF -DSDLMIXER_MOD=OFF -DSDLMIXER_MP3=OFF \
        -DSDLMIXER_MIDI=OFF -DSDLMIXER_OPUS=OFF -DSDLMIXER_VORBIS_STB=OFF \
        -DSDLMIXER_VORBIS_VORBISFILE=OFF -DSDLMIXER_WAVPACK=OFF
    cmake --build "$bld"
}

ASAN='-fsanitize=address -fno-omit-frame-pointer -g -O0'
build_mixer "$D/SDL_mixer-vuln-src"      "$D/mixer-aiff-vuln-asan-build"  "$ASAN" '-fsanitize=address'
build_mixer "$D/SDL_mixer-aiff-fixed-src" "$D/mixer-aiff-fixed-asan-build" "$ASAN" '-fsanitize=address'
build_mixer "$D/SDL_mixer-vuln-src"      "$D/mixer-aiff-vuln-nossp-build" '-fno-stack-protector -g -O0' ''
echo BUILD_OK
