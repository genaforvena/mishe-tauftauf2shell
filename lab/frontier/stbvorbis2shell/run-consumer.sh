#!/bin/sh
# W206: replay the real-consumer lane. SDL_mixer's own vendored stb_vorbis
# v1.22 is compiled into libSDL3_mixer.a with SDLMIXER_VORBIS_STB=ON. The
# driver calls only the public MIX_LoadAudio_IO() API with the crafted OGG.
# Fixed control: the same source + a one-line CODEBOOK_LIMIT check at the
# lookup_values calculation. Safe-input control: crafted file replaced by the
# 16-byte negative artifact. Build dirs and evidence are gitignored.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p consumer/evidence
printf 'not an ogg file\n' > evidence/safe-input.bin
SDM=../sdlmixer2shell/deps
SDL3DIR=$(CDPATH= cd -- "$SDM/SDL3-3.4.0-build" && pwd)
[ -n "$SDL3DIR" ] || exit 2
INC="-I$SDM/SDL3-3.4.0-build/include -I$SDM/SDL-release-3.2.4/include -I$SDM/SDL_mixer-vuln-src/include"
CFLAGS="-g -O0 -fsanitize=address -fno-omit-frame-pointer"
LIBS="-lSDL3_mixer -lSDL3 -lm -lpthread -ldl"
export LD_LIBRARY_PATH="$SDL3DIR"
export SDL_AUDIO_DRIVER=dummy
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1

# Fixed control source: a copy of the consumer tree with only the checked
# CODEBOOK_LIMIT line added to its vendored header. Rebuild from scratch so
# the fixed binary cannot inherit the vulnerable object.
if [ ! -f consumer/mix-fixed-src/src/stb_vorbis/stb_vorbis.h ]; then
    rm -rf consumer/mix-fixed-src
    cp -a "$SDM/SDL_mixer-vuln-src" consumer/mix-fixed-src
    python3 - <<'PY'
from pathlib import Path
p = Path('consumer/mix-fixed-src/src/stb_vorbis/stb_vorbis.h')
t = p.read_text()
needle = '         if (c->lookup_values == 0) return error(f, VORBIS_invalid_setup);\n'
assert t.count(needle) == 1
p.write_text(t.replace(needle, needle +
  '         if ((1 << 18) / c->entries < c->dimensions) return error(f, VORBIS_invalid_setup); /* W206 fixed control */\n'))
PY
fi

for kind in vuln fixed; do
    src="$SDM/SDL_mixer-vuln-src"
    bdir="consumer/mix-$kind-stb-asan"
    [ "$kind" = fixed ] && { src=consumer/mix-fixed-src; bdir=consumer/mix-fixed-stb-asan; }
    if [ ! -f "$bdir/libSDL3_mixer.a" ]; then
        cmake -S "$src" -B "$bdir" -DCMAKE_BUILD_TYPE=Debug \
            -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
            -DSDL3_DIR="$SDL3DIR" -DSDLMIXER_VORBIS_STB=ON \
            -DSDLMIXER_VORBIS_VORBISFILE=OFF -DSDLMIXER_VORBIS_TREMOR=OFF \
            -DBUILD_SHARED_LIBS=OFF -DSDLMIXER_TESTS=OFF -DSDLMIXER_EXAMPLES=OFF \
            > "consumer/mix-$kind-config.log" 2>&1 || exit 2
        cmake --build "$bdir" -j4 > "consumer/mix-$kind-build.log" 2>&1 || exit 2
    fi
    gcc $CFLAGS -o "consumer/mix-stb-$kind" consumer/mix-driver.c $INC \
        -L"$SDL3DIR" -L"$bdir" $LIBS || exit 2
done

./consumer/mix-stb-vuln evidence/chosen.ogg > consumer/evidence/vuln-attack.out 2>&1
VULN_RC=$?
./consumer/mix-stb-fixed evidence/chosen.ogg > consumer/evidence/fixed-attack.out 2>&1
FIXED_RC=$?
./consumer/mix-stb-vuln evidence/safe-input.bin > consumer/evidence/vuln-safe.out 2>&1
SAFE_RC=$?
printf 'vuln_attack_rc=%s fixed_attack_rc=%s vuln_safe_rc=%s\n' \
    "$VULN_RC" "$FIXED_RC" "$SAFE_RC"

PASS=0; FAIL=0
check() {
  if grep -qF "$2" "$3"; then
    PASS=$((PASS+1)); echo "PASS $1 $2"
  else
    FAIL=$((FAIL+1)); echo "FAIL $1 expected $2"
  fi
}
[ "$VULN_RC" -ne 0 ] && { PASS=$((PASS+1)); echo "PASS vuln_rejects rc=$VULN_RC"; } || { FAIL=$((FAIL+1)); echo 'FAIL vuln_rejects rc=0'; }
[ "$FIXED_RC" -eq 0 ] && { PASS=$((PASS+1)); echo "PASS fixed_clean rc=0"; } || { FAIL=$((FAIL+1)); echo "FAIL fixed_clean rc=$FIXED_RC"; }
[ "$SAFE_RC" -eq 0 ] && { PASS=$((PASS+1)); echo "PASS safe_clean rc=0"; } || { FAIL=$((FAIL+1)); echo "FAIL safe_clean rc=$SAFE_RC"; }
check vuln_asan 'ERROR: AddressSanitizer: heap-buffer-overflow' consumer/evidence/vuln-attack.out
check vuln_write 'WRITE of size 4' consumer/evidence/vuln-attack.out
check vuln_region '0 bytes after 8-byte region' consumer/evidence/vuln-attack.out
check vuln_frame 'MIX_LoadAudio_IO' consumer/evidence/vuln-attack.out
check vuln_frame 'STBVORBIS_init_audio' consumer/evidence/vuln-attack.out
check vuln_frame 'start_decoder' consumer/evidence/vuln-attack.out
check fixed_no_asan 'MIX_LoadAudio_IO=(nil)' consumer/evidence/fixed-attack.out
check safe_no_asan 'MIX_LoadAudio_IO=(nil)' consumer/evidence/vuln-safe.out
if grep -q 'AddressSanitizer' consumer/evidence/fixed-attack.out || grep -q 'AddressSanitizer' consumer/evidence/vuln-safe.out; then
  FAIL=$((FAIL+1)); echo 'FAIL controls_asan unexpected ASan report'
else
  PASS=$((PASS+1)); echo 'PASS controls_asan no ASan report in either control'
fi
echo "TOTAL PASS=$PASS FAIL=$FAIL"
echo '--- vulnerable ASan (first 12 lines) ---'
sed -n '1,12p' consumer/evidence/vuln-attack.out
echo '--- fixed ---'
cat consumer/evidence/fixed-attack.out
echo '--- safe ---'
cat consumer/evidence/vuln-safe.out
[ "$FAIL" -eq 0 ]
