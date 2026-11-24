#!/bin/sh
# W212: ASan-instrumented harness linked against the plain (non-ASan) pinned
# libraries. Run build-plain.sh first; this script does not rebuild the libs.
set -eu
cd "$(dirname "$0")"

FLAGS='-O0 -g -Wall -Wextra -fno-omit-frame-pointer -fsanitize=address'
cc $FLAGS -I src/include frame-datum.c \
  build-plain/crypto/libcrypto.a -lpthread -ldl -o frame-datum-vuln
cc $FLAGS -I src-fixed/include frame-datum.c \
  build-fixed-plain/crypto/libcrypto.a -lpthread -ldl -o frame-datum-fixed
echo 'frame-datum builds ready: frame-datum-vuln frame-datum-fixed'
