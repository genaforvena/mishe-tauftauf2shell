#!/bin/bash
# Build an in-process NetX Secure TLS client/server on the RAM network driver,
# with the server presenting the real 8192-bit oversized DER certificate.
# No host sockets, no external traffic.
set -e
HERE=$(cd "$(dirname "$0")" && pwd)
H=$(cd "$HERE/.." && pwd)
SRC=$(cd "$H/../src" && pwd)
VER=${1:-vuln}
SAFE=${2:-}
if [ "$VER" = fixed ]; then D="$SRC/netxduo-6.5.2.202603_rel"; U="inc-fixed"; else D="$SRC/netxduo-6.5.1.202602_rel"; U="inc-vuln"; fi
TX="$D/test/cmake/threadx"
INC="-I$HERE -I$H -I$H/$U -I$D/common/inc -I$D/crypto_libraries/inc -I$D/nx_secure/inc -I$D/nx_secure/ports -I$D/ports/linux/gnu/inc -I$TX/common/inc -I$TX/ports/linux/gnu/inc"
OUT="$HERE/tls_${VER}${SAFE:+_safe}_asan"
COMMON="-g -O0 -fno-omit-frame-pointer -no-pie -fsanitize=address -D_GNU_SOURCE -DTX_LINUX_MULTI_CORE -DNX_DISABLE_IPV6 -DNX_SECURE_ALLOW_SELF_SIGNED_CERTIFICATES -DTX_LINUX_MEMORY_SIZE=200000 $INC"
SAFEDEF=""; [ -n "$SAFE" ] && SAFEDEF="-DSAFE_CERT"

# The app must NOT see NX_SECURE_SOURCE_CODE: nx_secure_tls_api.h hides the
# public API declarations behind #ifndef NX_SECURE_SOURCE_CODE.
clang $COMMON $SAFEDEF -DNX_INCLUDE_USER_DEFINE_FILE -DTX_INCLUDE_USER_DEFINE_FILE \
  -c "$HERE/tls_ram.c" -o "$HERE/tls_ram_${VER}${SAFE:+_safe}.o" 2>"$HERE/build-app-$VER${SAFE:+_safe}.log" || {
    echo "APP COMPILE FAILED"; grep -n "error:" "$HERE/build-app-$VER${SAFE:+_safe}.log" | head -20; exit 1; }

clang $COMMON -DNX_SECURE_SOURCE_CODE -DNX_CRYPTO_SOURCE_CODE \
  -DNX_INCLUDE_USER_DEFINE_FILE -DTX_INCLUDE_USER_DEFINE_FILE \
  "$HERE/tls_ram_${VER}${SAFE:+_safe}.o" \
  "$D"/common/src/*.c "$D"/nx_secure/src/*.c "$D"/crypto_libraries/src/*.c \
  "$TX"/common/src/*.c "$TX"/ports/linux/gnu/src/*.c \
  -lpthread -lrt -o "$OUT" 2>"$HERE/build-asan-$VER${SAFE:+_safe}.log" || {
    echo "BUILD FAILED"; grep -n "error:" "$HERE/build-asan-$VER${SAFE:+_safe}.log" | head -30; exit 1; }
echo "built $OUT"
