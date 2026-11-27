#!/bin/sh
# Build verbatim pinned libmodplug trees twice: clang ASan with intra-object
# field padding (to see past-the-array writes) and a plain GCC control.
set -eu
cd "$(dirname "$0")"
for pin in vuln fixed; do
  cmake -S "src-$pin" -B "build-$pin-asan" \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS="-O1 -g -fsanitize=address -fsanitize-address-field-padding=2" \
    -DCMAKE_CXX_FLAGS="-O1 -g -fsanitize=address -fsanitize-address-field-padding=2" \
    -DBUILD_SHARED_LIBS=OFF >/dev/null
  cmake --build "build-$pin-asan" -j4 >/dev/null
  clang++ -DHAVE_STDINT_H -O1 -g -fsanitize=address -fsanitize-address-field-padding=2 \
    -I"src-$pin/src" -I"src-$pin/src/libmodplug" -I"build-$pin-asan" \
    harness.cpp "build-$pin-asan/libmodplug.a" -lm -o "harness-$pin-asan"
  cmake -S "src-$pin" -B "build-$pin-plain" \
    -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
    -DCMAKE_C_FLAGS="-O1 -g" -DCMAKE_CXX_FLAGS="-O1 -g" \
    -DBUILD_SHARED_LIBS=OFF >/dev/null
  cmake --build "build-$pin-plain" -j4 >/dev/null
  g++ -DHAVE_STDINT_H -O1 -g -I"src-$pin/src" -I"src-$pin/src/libmodplug" -I"build-$pin-plain" \
    harness.cpp "build-$pin-plain/libmodplug.a" -lm -o "harness-$pin-plain"
done
echo BUILD_OK
