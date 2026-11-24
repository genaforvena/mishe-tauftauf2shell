#!/bin/sh
# Build the loopback consumer against the pinned vulnerable (no-ASM ASan) and
# fixed libraries. All paths relative to this directory; no network access.
cd "$(dirname "$0")" || exit 2
set -e
FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O0"
cc $FLAGS -I src/include consumer.c build-asan-c/crypto/libcrypto.a \
  -lpthread -ldl -o consumer-vuln
cc $FLAGS -I src/include consumer.c build-fixed/crypto/libcrypto.a \
  -lpthread -ldl -o consumer-fixed
echo "built consumer-vuln and consumer-fixed"
