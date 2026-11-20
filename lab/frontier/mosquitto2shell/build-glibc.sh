#!/usr/bin/env bash
# Stock-glibc (no sanitizer) -O0 -g build of Mosquitto 2.1.2 for MASKerade
# Stage B heap work. Loopback-only lab; no host packages changed.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/../../src"
mkdir -p "$ROOT/logs"

CJSON_SRC="$ROOT/deps/cjson-stock"
CJSON_BUILD="$ROOT/deps/cjson-stock-build"
PREFIX="$ROOT/deps/cjson-stock-prefix"

if [ ! -f "$PREFIX/lib/libcjson.so" ]; then
  rm -rf "$CJSON_SRC" "$CJSON_BUILD" "$PREFIX"
  mkdir -p "$CJSON_SRC"
  tar xzf "$ROOT/deps/cjson.tar.gz" -C "$CJSON_SRC" --strip-components=1
  cmake -S "$CJSON_SRC" -B "$CJSON_BUILD" \
    -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON \
    -DENABLE_CJSON_TEST=OFF -DENABLE_CJSON_UTILS=OFF \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" > "$ROOT/logs/cjson-stock-cmake.log" 2>&1
  make -C "$CJSON_BUILD" -j4 > "$ROOT/logs/cjson-stock-make.log" 2>&1
  cmake --install "$CJSON_BUILD" > "$ROOT/logs/cjson-stock-install.log" 2>&1
fi

B="$ROOT/build-2.1.2-glibc"
rm -rf "$B"
cmake -S "$SRC/mosquitto-2.1.2" -B "$B" \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS="-O0 -g -fno-omit-frame-pointer" \
  -DCJSON_INCLUDE_DIR="$PREFIX/include" \
  -DCJSON_LIBRARY="$PREFIX/lib/libcjson.so" \
  -DcJSON_DIR="$PREFIX/lib/cmake/cJSON" \
  -DWITH_WEBSOCKETS=ON -DWITH_WEBSOCKETS_BUILTIN=ON \
  -DWITH_TLS=ON -DWITH_DOCS=OFF -DWITH_TESTS=OFF \
  > "$ROOT/logs/cmake-2.1.2-glibc.log" 2>&1
make -C "$B" -j4 > "$ROOT/logs/make-2.1.2-glibc.log" 2>&1
echo "BUILD OK: $B/src/mosquitto"
echo "Verify with: ldd $B/src/mosquitto   # no libasan/libubsan"
