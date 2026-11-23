#!/bin/sh
# Compile the file-level harnesses against one pinned OpenEXR build.
# usage: ./build.sh <build-root> <src-root> <out-dir> [asan|plain]
set -eu
BUILD=$1
SRC=$2
OUT=$3
MODE=${4:-plain}
mkdir -p "$OUT"
CORE="$BUILD/src/lib/OpenEXRCore"
GEN="$BUILD/cmake"
IMATH_COMPAT="$BUILD/OpenEXR_ImathIncludeCompat"
IMATH_CONFIG="$BUILD/_deps/imath-build/config"
IMATH_SRC="$BUILD/_deps/imath-src/src"
OPENEXR_SRC="$SRC/src/lib"
LIBS="$BUILD/src/lib/OpenEXRUtil/libOpenEXRUtil*.a $BUILD/src/lib/OpenEXR/libOpenEXR-3_5*.a $BUILD/src/lib/OpenEXRCore/libOpenEXRCore*.a $BUILD/src/lib/IlmThread/libIlmThread*.a $BUILD/src/lib/Iex/libIex*.a"
IMATH_LIB=$(find "$BUILD/_deps" -name 'libImath*.a' | sort | tr '\n' ' ')
INC="-I$CORE -I$SRC/src/lib/OpenEXRCore -I$GEN -I$IMATH_COMPAT -I$IMATH_CONFIG -I$IMATH_SRC -I$OPENEXR_SRC/OpenEXR -I$OPENEXR_SRC/Iex -I$OPENEXR_SRC/IlmThread"
SAN=""
if [ "$MODE" = asan ]; then SAN="-fsanitize=address -fno-omit-frame-pointer -g -O1"; fi
set -x
gcc $SAN -g -O1 $INC harness/flat_harness.c $LIBS $IMATH_LIB -ldeflate -lzstd -lz -lpthread -lstdc++ -lm -o "$OUT/flat_harness"
gcc $SAN -g -O1 $INC harness/guarded_harness.c $LIBS $IMATH_LIB -ldeflate -lzstd -lz -lpthread -lstdc++ -lm -o "$OUT/guarded_harness"
g++ $SAN -g -O1 $INC cases/gen_baseline.cpp $LIBS $IMATH_LIB -ldeflate -lzstd -lz -lpthread -lm -o "$OUT/gen_baseline"
g++ $SAN -g -O1 $INC cases/cpp_singlepass.cpp $LIBS $IMATH_LIB -ldeflate -lzstd -lz -lpthread -lm -o "$OUT/cpp_singlepass"
