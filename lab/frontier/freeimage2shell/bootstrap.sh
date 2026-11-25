#!/usr/bin/env bash
set -euo pipefail
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
JOBS=${JOBS:-4}
(cd pins && sha256sum -c SHA256SUMS)
mkdir -p src harness evidence
for v in 3.19.24 3.19.25; do
    if [[ ! -d src/freeimage-$v ]]; then
        tar -xzf pins/freeimage-$v.tar.gz -C src
    fi
done
common=(
    -DBUILD_SHARED_LIBS=OFF -DFREEIMAGE_STATIC=ON -DBUILD_TESTS=OFF
    -DBUILD_JXR=OFF -DBUILD_LIBRAWLITE=OFF -DBUILD_OPENEXR=OFF
)
for kind in vuln fixed; do
    if [[ $kind == vuln ]]; then v=3.19.24; else v=3.19.25; fi
    cmake -S "src/freeimage-$v" -B "build-$kind-asan" -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        "${common[@]}" -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1 -w' \
        -DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1 -w' \
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address'
    cmake --build "build-$kind-asan" -j"$JOBS"
    c++ -std=c++17 -g -O1 -fsanitize=address -fno-omit-frame-pointer -DFREEIMAGE_LIB \
        -I"src/freeimage-$v/Source" harness/driver.cpp "build-$kind-asan/libFreeImage.a" \
        -lm -lpthread -o "harness/$kind-asan"
done
cmake -S src/freeimage-3.19.24 -B build-vuln-plain -DCMAKE_BUILD_TYPE=Release \
    "${common[@]}" -DCMAKE_C_FLAGS='-O2 -w' -DCMAKE_CXX_FLAGS='-O2 -w'
cmake --build build-vuln-plain -j"$JOBS"
c++ -std=c++17 -O2 -g -DFREEIMAGE_LIB -Isrc/freeimage-3.19.24/Source \
    harness/driver.cpp build-vuln-plain/libFreeImage.a -lm -lpthread -o harness/vuln-plain
