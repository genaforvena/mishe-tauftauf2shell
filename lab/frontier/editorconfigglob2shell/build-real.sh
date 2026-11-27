#!/bin/sh
# Offline rebuild of the four harness consumers from the pinned archives.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p work

if [ ! -d work/src-vuln ]; then
    tar -xzf pins/source-parent.tar.gz -C work
    mv work/editorconfig-core-c-b4724e475571 work/src-vuln
fi
if [ ! -d work/src-fixed ]; then
    cp -a work/src-vuln work/src-fixed
    (cd work/src-fixed && patch -p1 --silent < "$ROOT/pins/fix.patch")
fi

build_one() {
    src=$1
    label=$2
    flags=$3
    cmake -S "$src" -B "work/build-$label" -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="$flags" > "work/cmake-$label.log" 2>&1
    cmake --build "work/build-$label" --target editorconfig_static -j4 >> "work/cmake-$label.log" 2>&1
    gcc -g -O0 $flags \
        -I "work/build-$label/src/auto" -I "$src/include" -I "$src/src/lib" \
        -o "work/ecglob-$label" harness/ecglob_harness.c \
        "work/build-$label/lib/libeditorconfig_static.a" -lpcre2-8
    echo "BUILD_OK $label"
}

build_one work/src-vuln vuln-asan '-fsanitize=address -fno-stack-protector'
build_one work/src-fixed fixed-asan '-fsanitize=address -fno-stack-protector'
build_one work/src-vuln vuln-plain '-fno-stack-protector'
build_one work/src-fixed fixed-plain '-fno-stack-protector'
