#!/bin/sh
# Replay the imagemagick2shell evidence matrix from the repo root or this dir.
# All inputs are local; nothing is opened on a network.
set -u
cd "$(dirname "$0")" || exit 1
DEFS='-DMAGICKCORE_HDRI_ENABLE=1 -DMAGICKCORE_QUANTUM_DEPTH=16 -DMAGICKCORE_CHANNEL_MASK_DEPTH=32'
ASAN='-g -O1 -fsanitize=address -fno-omit-frame-pointer'
PLAIN='-g -O0'
LIBS='-lm -lpthread'

build() {
  name=$1; ccflags=$2; inc1=$3; inc2=$4; lib=$5
  gcc $ccflags $DEFS -I "$inc1" -I "$inc2" harness.c "$lib" $LIBS -o "$name" 2>&1 ||
    { echo "BUILD FAIL $name"; exit 1; }
}

{
  echo "=== imagemagick2shell evidence $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  echo "--- pins ---"
  sha256sum -c PINS.sha256 2>&1
  echo "--- builds ---"
  build harness-asan "$ASAN" vuln vuln vuln/MagickCore/.libs/libMagickCore-7.Q16HDRI.a
  build harness-fixed "$ASAN" fixed-build fixed fixed-build/MagickCore/.libs/libMagickCore-7.Q16HDRI.a
  build harness-plain "$PLAIN" plain-build vuln plain-build/MagickCore/.libs/libMagickCore-7.Q16HDRI.a
  echo "built harness-asan harness-fixed harness-plain"

  for bin in harness-asan harness-fixed harness-plain; do
    for args in '2 2 2 2 control' '1 1 8 4 attack'; do
      set -- $args
      ASAN_OPTIONS=detect_leaks=0 "./$bin" "$1" "$2" "$3" "$4" > .case.out 2>&1
      rc=$?
      head -14 .case.out
      echo "rc=$rc"
    done
  done


  echo "--- gdb chosen bytes, plain attack ---"
  if command -v gdb >/dev/null 2>&1; then
    gdb -q -batch \
      -ex 'break harness.c:154' \
      -ex 'run 1 1 8 4' \
      -ex 'p/x stream_info->pixels[0]@24' \
      -ex 'p stream_info->pixels' \
      ./harness-plain 2>&1 | head -40
  else
    echo 'gdb UNKNOWN: not installed'
  fi
  echo "=== end ==="
} 2>&1 | tee evidence.log
