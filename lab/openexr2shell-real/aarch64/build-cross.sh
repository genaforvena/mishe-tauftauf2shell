#!/bin/sh
# Cross-build OpenEXRCore (C library) for aarch64 from the pinned release tree.
# Usage: build-cross.sh <version: 3.5.2|3.5.3> <x86 build tree: build-vuln-plain|build-fixed-plain> <tag: vuln|fixed>
# The x86 build tree supplies only generated headers (OpenEXRConfig.h, Imath
# config and compat headers); all objects here are compiled by the aarch64
# cross compiler from the pinned upstream C sources.
set -eu
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
VER=${1:?version}
XB=${2:?x86 build tree supplying generated headers}
TAG=${3:?tag}
OUT="$LAB/aarch64/core-$TAG"
SYS="$LAB/aarch64/sysroot"
mkdir -p "$OUT"
rm -f "$OUT"/*.o "$OUT"/*.a

INC="-I$LAB/$XB/src/lib/OpenEXRCore -I$LAB/src/openexr-$VER/src/lib/OpenEXRCore -I$LAB/src/openexr-$VER/external/OpenJPH/src/core -I$LAB/$XB/cmake -I$LAB/$XB/_deps/imath-src/src/Imath -I$LAB/$XB/_deps/imath-src/src -I$LAB/$XB/_deps/imath-build/config -I$LAB/$XB/OpenEXR_ImathIncludeCompat"
DEFS="-DLIBDEFLATE_DLL -D_FILE_OFFSET_BITS=64"
CFLAGS="-O2 -g -O3 -DNDEBUG -fPIC -fvisibility=hidden $DEFS $INC"

for f in "$LAB"/src/openexr-$VER/src/lib/OpenEXRCore/*.c; do
  b=$(basename -- "$f" .c)
  aarch64-linux-gnu-gcc $CFLAGS -c "$f" -o "$OUT/$b.o"
done
# OpenEXRCore has one C++ translation unit; cross C++ headers are absent, so
# clang targets aarch64 with the host libstdc++ headers (arch-neutral here).
clang++ --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu \
  -O2 -g -DNDEBUG $DEFS $INC -I/usr/include/c++/13 \
  -I/usr/include/x86_64-linux-gnu/c++/13 \
  -c "$LAB/src/openexr-$VER/src/lib/OpenEXRCore/internal_ht.cpp" \
  -o "$OUT/internal_ht.o"
clang++ --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu \
  -O2 -g -DNDEBUG $DEFS $INC -I/usr/include/c++/13 \
  -I/usr/include/x86_64-linux-gnu/c++/13 \
  -c "$LAB/src/openexr-$VER/src/lib/OpenEXRCore/internal_ht_common.cpp" \
  -o "$OUT/internal_ht_common.o"
# OpenJPH's generic C++ sources are part of the Core archive; SSE/AVX variants
# are excluded because they cannot compile for aarch64.
OJPH_INC="-I$LAB/$XB/external/OpenJPH/src/core -I$LAB/src/openexr-$VER/external/OpenJPH/src/core -I$LAB/src/openexr-$VER/external/OpenJPH/src/core/openjph -I$LAB/src/openexr-$VER/external/OpenJPH/src/core/shared"
find "$LAB/src/openexr-$VER/external/OpenJPH/src/core" -name '*.cpp' \
  | grep -v -E '_(sse|sse2|ssse3|avx|avx2|avx512|vsx|wasm)\.cpp$' \
  | while IFS= read -r f; do
      d=$(basename -- "$(dirname -- "$f")")
      b=$(basename -- "$f" .cpp)
      clang++ --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu \
        -O2 -g -DNDEBUG -std=gnu++14 -D_FILE_OFFSET_BITS=64 $OJPH_INC -I/usr/include/c++/13 \
        -I/usr/include/x86_64-linux-gnu/c++/13 \
        -c "$f" -o "$OUT/ojph_${d}_${b}.o"
    done
clang --target=aarch64-linux-gnu --sysroot=/usr/aarch64-linux-gnu \
  -O2 -g -DNDEBUG -DOJPH_ALIGNED_ALLOC_EXISTS -D_FILE_OFFSET_BITS=64 \
  $OJPH_INC -c "$LAB/src/openexr-$VER/external/OpenJPH/src/core/others/ojph_mem_c.c" \
  -o "$OUT/ojph_mem_c.o"
aarch64-linux-gnu-ar rcs "$OUT/libOpenEXRCore.a" "$OUT"/*.o

for h in flat_harness guarded_harness tiled_harness; do
  [ -f "$LAB/harness/$h.c" ] || continue
  aarch64-linux-gnu-gcc -O2 -g $DEFS $INC "$LAB/harness/$h.c" "$OUT/libOpenEXRCore.a" \
    "$SYS/usr/lib/aarch64-linux-gnu/libzstd.so.1" \
    "$SYS/usr/lib/aarch64-linux-gnu/libdeflate.so.0" \
    "$SYS/usr/lib/aarch64-linux-gnu/libz.so.1" \
    /usr/aarch64-linux-gnu/lib/libstdc++.so.6 -lpthread -lm -o "$LAB/aarch64/${h}-$TAG"
done
echo "CROSS BUILD OK $TAG (OpenEXR $VER)"
