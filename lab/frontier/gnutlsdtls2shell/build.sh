#!/bin/sh
# Provision pinned nettle 3.10 and build both pinned GnuTLS releases with ASan.
# Idempotent: skips any stage whose output already exists.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
cd "$HERE"
OPT="$HERE/opt"
PP="$OPT/lib64/pkgconfig"

if [ ! -f "$OPT/lib64/libnettle.a" ]; then
  tar xzf src/nettle-3.10.tar.gz -C src
  mkdir -p build-nettle-3.10
  ( cd build-nettle-3.10 && \
    ../src/nettle-3.10/configure --prefix="$OPT" --disable-documentation >configure.log 2>&1 && \
    make -j4 >make.log 2>&1 && make install >install.log 2>&1 )
fi

for V in 3.8.12 3.8.13; do
  [ -f "src/gnutls-$V.tar.xz" ] || curl -sSL --max-time 120 -o "src/gnutls-$V.tar.xz" \
    "https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/gnutls-$V.tar.xz"
  [ -d "src/gnutls-$V" ] || tar xJf "src/gnutls-$V.tar.xz" -C src
  B="build-$V-asan"
  [ -f "$B/lib/.libs/libgnutls.so" ] && continue
  mkdir -p "$B"
  ( cd "$B" && \
    PKG_CONFIG_PATH="$PP" \
    CFLAGS='-fsanitize=address -g -O1 -fno-omit-frame-pointer' \
    LDFLAGS='-fsanitize=address' \
    "../src/gnutls-$V/configure" --disable-doc --disable-guile --disable-nls \
      --without-tpm --without-tpm2 --disable-full-test-suite \
      --with-included-unistring >configure.log 2>&1 && \
    make -C gl -j4 >>make-lib.log 2>&1 && \
    make -C lib -j4 >>make-lib.log 2>&1 )
done
echo "BUILD OK"
