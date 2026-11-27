#!/bin/sh
# Rebuild the pinned OpenJPH trees and the direct-sink harnesses.
# No upstream source is edited; both tarballs are verbatim GitHub archives.
set -eu
cd "$(dirname "$0")"
(cd pins && sha256sum -c SHA256SUMS >/dev/null)

for pin in vuln fixed; do
  if [ ! -f "src-$pin/src/core/codestream/ojph_codeblock.cpp" ]; then
    mkdir -p "src-$pin"
    tar xzf "pins/$pin.tar.gz" -C "src-$pin" --strip-components=1
  fi
  for mode in asan plain; do
    if [ "$mode" = asan ]; then build_type=asan; else build_type=Release; fi
    cmake -S "src-$pin" -B "build-$pin-$mode" \
      -DCMAKE_BUILD_TYPE="$build_type" \
      -DOJPH_DISABLE_SIMD=ON -DOJPH_ENABLE_TIFF_SUPPORT=OFF \
      -DBUILD_TESTING=OFF >/dev/null 2>&1
    cmake --build "build-$pin-$mode" -j4 --target ojph_expand ojph_compress \
      >/dev/null 2>&1
  done
done

INC="-Isrc-vuln/src/core/coding -Isrc-vuln/src/core/openjph"
g++ -fsanitize=address -O1 -g $INC sink.cpp \
  -Lbuild-vuln-asan/src/core -lopenjph \
  -Wl,-rpath,'$ORIGIN/build-vuln-asan/src/core' -o sink-vuln-asan
g++ -O1 -g $INC sink.cpp \
  -Lbuild-vuln-plain/src/core -lopenjph \
  -Wl,-rpath,'$ORIGIN/build-vuln-plain/src/core' -o sink-vuln-plain
echo BUILD_OK
