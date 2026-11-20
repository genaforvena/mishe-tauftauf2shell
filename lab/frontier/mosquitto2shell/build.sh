#!/usr/bin/env bash
# Reproducible ASan/UBSan build of Mosquitto 2.1.2 (affected) and 2.1.3
# (fixed) for CVE-2026-110486 / MASKerade. Loopback-only lab.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
SRC="$ROOT/../../src"
mkdir -p "$ROOT/logs"

SAN="-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g"
CJSON="$ROOT/deps/cjson"

for v in 2.1.2 2.1.3; do
  b="$ROOT/build-$v-asan"
  rm -rf "$b"
  echo "=== cmake $v ==="
  cmake -S "$SRC/mosquitto-$v" -B "$b" \
    -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$SAN" \
    -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address,undefined" \
    -DCJSON_INCLUDE_DIR="$CJSON/include" \
    -DCJSON_LIBRARY="$CJSON/lib/libcjson.so" \
    -DcJSON_DIR="$CJSON/lib/cmake/cJSON" \
    -DWITH_WEBSOCKETS=ON \
    -DWITH_WEBSOCKETS_BUILTIN=ON \
    -DWITH_TLS=ON \
    -DWITH_DOCS=OFF \
    -DWITH_TESTS=OFF \
    > "$ROOT/logs/cmake-$v.log" 2>&1 || { cat "$ROOT/logs/cmake-$v.log"; exit 1; }
  echo "=== make $v ==="
  make -C "$b" -j4 > "$ROOT/logs/make-$v.log" 2>&1 || { tail -60 "$ROOT/logs/make-$v.log"; exit 1; }
  ls -l "$b/src/mosquitto"
done
echo "BUILD OK"
