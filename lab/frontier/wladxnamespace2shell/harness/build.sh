#!/bin/sh
# Build the pinned WLA DX v10.7 (vulnerable) and v10.8 (fixed) wlalink arms.
set -eu
cd "$(dirname "$0")"
SRC=../src
VULN=$SRC/wla-dx-10.7
FIXED=$SRC/wla-dx-10.8
VCOMMIT=91c52b1f4ef3cc8ba3c0638f7536539579af6a9f
FCOMMIT=887e74809d26d4f58130e62ae525f1c29790b490

fetch() {
  dir=$1; tag=$2; commit=$3
  if [ ! -d "$dir/.git" ]; then
    mkdir -p "$SRC"
    git clone -q --depth 1 --branch "$tag" https://github.com/vhelin/wla-dx.git "$dir"
  fi
  got=$(git -C "$dir" rev-parse HEAD)
  if [ "$got" != "$commit" ]; then
    echo "SOURCE_COMMIT_MISMATCH $dir $got != $commit" >&2
    exit 1
  fi
}
fetch "$VULN" v10.7 "$VCOMMIT"
fetch "$FIXED" v10.8 "$FCOMMIT"

cmake -S "$VULN" -B ../build-vuln-asan -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' >/dev/null
cmake --build ../build-vuln-asan --target wla-6502 wlalink -j8 >/dev/null
cmake -S "$FIXED" -B ../build-fixed-asan -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O0' -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' >/dev/null
cmake --build ../build-fixed-asan --target wla-6502 wlalink -j8 >/dev/null
cmake -S "$VULN" -B ../build-vuln-plain -DCMAKE_C_FLAGS='-O0 -g -fno-stack-protector' >/dev/null
cmake --build ../build-vuln-plain --target wla-6502 wlalink -j8 >/dev/null
echo BUILD_OK
