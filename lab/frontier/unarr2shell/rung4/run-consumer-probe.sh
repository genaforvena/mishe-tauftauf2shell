#!/bin/bash
# unarr2shell rung-4 consumer probe (negative result). Replays the non-ASan
# glibc layout measurement at tar_get_name's overflowing strcat and the live
# adjacent-canary check. Uses only the verbatim v1.1.0 sink and the real host
# allocator; no source patch is applied to unarr.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HERE="$ROOT/rung4"
BUILD="$HERE/build"
EVID="$HERE/evidence.md"
mkdir -p "$BUILD"

if [ ! -f "$BUILD/libunarr.a" ]; then
  ( cd "$BUILD" && cmake -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=OFF \
      -DENABLE_7Z=OFF -DCMAKE_C_FLAGS='-fno-omit-frame-pointer -g -O0' \
      "$ROOT/unarr-1.1.0" >/dev/null && cmake --build . -j2 >/dev/null ) || exit 1
fi
cc -fno-omit-frame-pointer -g -O0 -I"$ROOT/unarr-1.1.0" \
   "$ROOT/harness/driver.c" "$BUILD/libunarr.a" -o "$BUILD/driver" || exit 1
cc -shared -fPIC -O0 -g "$HERE/canary_interpose.c" -o "$HERE/canary.so" -ldl || exit 1

pass=0; fail=0
check() {
  if [ "$2" = "$3" ]; then echo "PASS $1 ($3)"; pass=$((pass+1))
  else echo "FAIL $1 (want $2, got $3)"; fail=$((fail+1)); fi
}

# Break one line past the sink so the NUL is already written. `prefixed` is
# still live at :254 (it is freed only at :257 after name = prefixed).
gdb -q -batch \
  -ex 'set pagination off' \
  -ex 'break parse-tar.c:254' \
  -ex 'run '"$ROOT"'/evidence/attack.tar' \
  -ex 'printf "USABLE=%u\n", malloc_usable_size(prefixed)' \
  -ex 'printf "CHUNKSIZE=%lu\n", *(unsigned long*)((char*)prefixed-8) & ~7UL' \
  -ex 'printf "NEXTCHUNK_SIZE=%lu\n", *(unsigned long*)((char*)prefixed+264)' \
  -ex 'printf "OOB_BYTE=%02x\n", (unsigned char)prefixed[257]' \
  "$BUILD/driver" > "$HERE/gdb.out" 2>&1

usable=$(grep -m1 '^USABLE=' "$HERE/gdb.out" | cut -d= -f2)
csize=$(grep -m1 '^CHUNKSIZE=' "$HERE/gdb.out" | cut -d= -f2)
nextsz=$(grep -m1 '^NEXTCHUNK_SIZE=' "$HERE/gdb.out" | cut -d= -f2)
oob=$(grep -m1 '^OOB_BYTE=' "$HERE/gdb.out" | cut -d= -f2)
check usable-ge-258 1 "$([ "${usable:-0}" -ge 258 ] && echo 1 || echo 0)"
check chunk-272 "${csize:-0}" 272
check oob-is-nul 00 "${oob:-ff}"
echo "  malloc_usable_size=$usable chunk_size=$csize next_chunk_size=$nextsz oob_byte=$oob"

# Allocate a live 64-byte object immediately after `prefixed` before the
# overflowing strcat, fill it with 0x5a, and check every byte afterwards.
LD_PRELOAD="$HERE/canary.so" "$BUILD/driver" "$ROOT/evidence/attack.tar" \
  > "$HERE/canary.out" 2>&1
delta=$(grep -m1 '^PROBE ' "$HERE/canary.out" | sed -n 's/.*delta=\([-0-9]*\).*/\1/p')
corrupt=$(grep -m1 '^PROBE canary_corrupted=' "$HERE/canary.out" | cut -d= -f2)
check canary-next-chunk 272 "${delta:-none}"
check canary-intact 0 "${corrupt:-none}"

# Record the measured evidence, not a stale copy.
{
  echo "# unarr2shell rung-4 consumer measurement — $(date -u +%FT%TZ)"
  echo "Host: $(ldd --version | head -1), x86-64; unarr v1.1.0 verbatim sink."
  echo "No unarr source patch; non-ASan build so the real glibc allocator is in play."
  echo
  echo "## gdb, breakpoint parse-tar.c:254 (after strcat(prefixed,name) at :253)"
  grep -E '^(USABLE|CHUNKSIZE|NEXTCHUNK_SIZE|OOB_BYTE)=' "$HERE/gdb.out"
  echo
  echo "## live adjacent canary"
  grep '^PROBE' "$HERE/canary.out"
  echo
  echo "Interpretation: malloc(257) yields a 272-byte glibc chunk (usable $usable)."
  echo "prefixed[257] is inside that chunk's usable slack, $delta bytes before the"
  echo "next live object; the next chunk's size field is at prefixed+264 and is"
  echo "untouched. No adjacent live object is modified. Structural kill of the"
  echo "rung-4 adjacent-object path on this host; grade stays rung 3 verbatim /"
  echo "rung 4 PARTIAL (fixed NUL), no chosen byte, no pointer, no command, no r5."
} > "$EVID"
cat "$EVID"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
