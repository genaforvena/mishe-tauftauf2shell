#!/usr/bin/env bash
# One-command replay of the real-library lane from a clean archive.
# Provisioning fetches pinned upstream source; all execution stays local.
set -eu
cd "$(dirname "$0")"
FIX=c493a776e6bc6cfb1d8d15152a0b74f3d15b33fd

if [ ! -d src/.git ]; then
  git clone -q --filter=blob:none --no-checkout \
    https://github.com/DanBloomberg/leptonica.git src
  git -C src checkout -q 1.87.0
fi
if [ ! -d src-fixed/.git ]; then
  git -C src worktree add -q ../src-fixed "$FIX"
fi

for pair in 'src build-vuln' 'src-fixed build-fixed'; do
  set -- $pair
  cmake -S "$1" -B "$2" -DCMAKE_BUILD_TYPE=Debug -DBUILD_PROG=OFF \
    -DSW_BUILD=OFF -DENABLE_ZLIB=OFF -DENABLE_PNG=OFF -DENABLE_GIF=OFF \
    -DENABLE_JPEG=OFF -DENABLE_TIFF=OFF -DENABLE_WEBP=OFF \
    -DENABLE_OPENJPEG=OFF \
    -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' \
    -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
    -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address' >/dev/null
  cmake --build "$2" -j4 >/dev/null
done

bash run-real.sh
