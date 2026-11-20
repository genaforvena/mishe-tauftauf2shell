#!/usr/bin/env bash
# Provision cJSON 1.7.17 for both Mosquitto build lanes.
# Fetch + sha256 verification only; builds a local dependency, no network probe.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DEPS="$HERE/deps"
mkdir -p "$DEPS"
cd "$DEPS"
TAR=cjson.tar.gz
SHA=c91d1eeb7175c50d49f6ba2a25e69b46bd05cffb798382c19bfb202e467ec51c
URL=https://github.com/DaveGamble/cJSON/archive/refs/tags/v1.7.17.tar.gz
if [ ! -f "$TAR" ]; then
  curl -fsSL --retry 2 --max-time 300 -o "$TAR" "$URL"
fi
echo "$SHA  $TAR" | sha256sum -c -
# ASan lane expects deps/cjson with include/, lib/libcjson.so and lib/cmake/cJSON.
if [ ! -f cjson/lib/libcjson.so ]; then
  rm -rf cJSON-1.7.17
  tar -xzf "$TAR"
  cmake -S cJSON-1.7.17 -B cjson-build \
    -DCMAKE_BUILD_TYPE=Debug -DBUILD_SHARED_LIBS=ON \
    -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer -O1 -g" \
    -DCMAKE_INSTALL_PREFIX="$DEPS/cjson" \
    >/dev/null
  cmake --build cjson-build --target install -j4 >/dev/null
fi
# Stock-glibc lane expects cjson.tar.gz and builds deps/cjson-stock-prefix itself.
echo "cJSON 1.7.17 verified at $DEPS/$TAR"
