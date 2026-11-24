#!/bin/sh
# Rebuild both snap7shell harness variants from the pinned pristine tarball.
# All paths relative to this directory. Lab-only; no network access here.
set -e
cd "$(dirname "$0")"
sha256sum -c <<'EOF'
2840d50a833d928e5175b8ccc5383fae0fcc3e826c07e60b2b4190a30c613c36  snap7-30f37da.tar.gz
EOF
rm -rf src-vuln src-fixed
mkdir src-vuln src-fixed
tar xzf snap7-30f37da.tar.gz --strip-components=1 -C src-vuln
tar xzf snap7-30f37da.tar.gz --strip-components=1 -C src-fixed
patch -s -p1 -d src-vuln < isotcp-testdouble.patch
patch -s -p1 -d src-fixed < isotcp-testdouble.patch
patch -s -p1 -d src-fixed < fix-readmultivars.patch
for v in vuln fixed; do
  g++ -std=c++11 -fsanitize=address -fno-omit-frame-pointer -g -O0 \
    -I src-$v/src/core -I src-$v/src/lib -I src-$v/src/sys \
    harness.cpp src-$v/src/core/*.cpp src-$v/src/lib/*.cpp src-$v/src/sys/*.cpp \
    -lpthread -o $v
done
echo "BOOTSTRAP OK"
