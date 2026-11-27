#!/bin/sh
# Rebuild the pinned libmodplug harnesses from the two tarballs in pins/.
# clang array-bounds sanitizer makes the intra-object array overrun visible;
# plain GCC records the resulting Order[] state corruption.
set -eu
cd "$(dirname "$0")"
(cd pins && sha256sum -c SHA256SUMS >/dev/null)
for pin in vuln fixed; do
  if [ ! -f "src-$pin/src/load_dsm.cpp" ]; then
    mkdir -p "src-$pin"
    tar xzf "pins/$pin.tar.gz" -C "src-$pin" --strip-components=1
  fi
  cmake -S "src-$pin" -B "build-$pin-bounds" \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_C_FLAGS='-O1 -g -fsanitize=array-bounds' \
    -DCMAKE_CXX_FLAGS='-O1 -g -fsanitize=array-bounds' \
    -DBUILD_SHARED_LIBS=OFF >/dev/null 2>&1
  cmake --build "build-$pin-bounds" -j4 >/dev/null 2>&1
  clang++ -DHAVE_STDINT_H -O1 -g -fsanitize=array-bounds \
    -I"src-$pin/src" -I"src-$pin/src/libmodplug" -I"build-$pin-bounds" \
    harness.cpp "build-$pin-bounds/libmodplug.a" -lm -o "harness-$pin-bounds"
  cmake -S "src-$pin" -B "build-$pin-plain" \
    -DCMAKE_C_COMPILER=gcc -DCMAKE_CXX_COMPILER=g++ \
    -DCMAKE_C_FLAGS='-O1 -g' -DCMAKE_CXX_FLAGS='-O1 -g' \
    -DBUILD_SHARED_LIBS=OFF >/dev/null 2>&1
  cmake --build "build-$pin-plain" -j4 >/dev/null 2>&1
  g++ -DHAVE_STDINT_H -O1 -g \
    -I"src-$pin/src" -I"src-$pin/src/libmodplug" -I"build-$pin-plain" \
    harness.cpp "build-$pin-plain/libmodplug.a" -lm -o "harness-$pin-plain"
done
echo BUILD_OK
