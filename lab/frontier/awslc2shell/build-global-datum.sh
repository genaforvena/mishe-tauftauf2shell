#!/bin/sh
# W208: compile the global-datum probe against the already-built plain pinned
# libraries (run build-plain.sh first). No library rebuild needed.
set -eu
cd "$(dirname "$0")"

FLAGS='-O0 -g -Wall -Wextra'
cc $FLAGS -I src/include global-datum.c \
  build-plain/crypto/libcrypto.a -lpthread -ldl -o global-datum-vuln
cc $FLAGS -I src-fixed/include global-datum.c \
  build-fixed-plain/crypto/libcrypto.a -lpthread -ldl -o global-datum-fixed
echo 'global-datum builds ready: global-datum-vuln global-datum-fixed'
