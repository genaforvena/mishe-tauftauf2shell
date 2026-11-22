#!/bin/bash
# Build the real pinned NetX Secure X.509 verification path under ASan.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../src" && pwd)
cp "$SRC/netx-oversized-key-test-data.h" "$HERE/nx_oversized_key_test_data.h"

for V in vuln fixed; do
  if [ "$V" = vuln ]; then D="$SRC/netxduo-6.5.1.202602_rel"; else D="$SRC/netxduo-6.5.2.202603_rel"; fi
  TX="$D/test/cmake/threadx"
  INC="-I$HERE -I$D/common/inc -I$D/crypto_libraries/inc -I$D/nx_secure/inc -I$D/nx_secure/ports -I$D/ports/linux/gnu/inc -I$TX/common/inc -I$TX/ports/linux/gnu/inc"
  mkdir -p "$HERE/inc-$V"
  cp "$D/common/inc/nx_user_sample.h" "$HERE/inc-$V/nx_user.h"
  cp "$D/nx_secure/ports/nx_secure_user_sample.h" "$HERE/inc-$V/nx_secure_user.h" 2>/dev/null || true
  INC="-I$HERE/inc-$V $INC"

  clang -g -O0 -fsanitize=address -fno-omit-frame-pointer \
    -DNX_SECURE_SOURCE_CODE -DNX_CRYPTO_SOURCE_CODE \
    -DNX_INCLUDE_USER_DEFINE_FILE -DTX_INCLUDE_USER_DEFINE_FILE $INC \
    "$HERE/netx_oversized.c" \
    "$D"/nx_secure/src/nx_secure_x509*.c \
    "$HERE/stubs.c" \
    "$D"/crypto_libraries/src/nx_crypto_rsa.c \
    "$D"/crypto_libraries/src/nx_crypto_huge_number.c \
    "$D"/crypto_libraries/src/nx_crypto_huge_number_extended.c \
    -o "$HERE/netx_$V" 2>"$HERE/build-$V.log" || {
      echo "BUILD $V FAILED"; tail -40 "$HERE/build-$V.log"; exit 1; }
  echo "built $HERE/netx_$V"
done
