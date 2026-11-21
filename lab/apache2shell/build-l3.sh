#!/usr/bin/env bash
# Reproducible ASan/UBSan build for adjacent lane L3
# (CVE-2026-57941, mod_http2 shared session->bbtmp re-entrancy / wild write).
# 2.4.68 affected; 2.4.69 control (per-call brigades + m_stream_cleanup guard
# + separate iqueue pool). Reuses the pinned loopback-only nghttp2 1.64.0.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ROOT="$HERE/l3"
SRC="$REPO/lab/src"
NG_PREFIX="$REPO/lab/frontier/apache2root/deps/nghttp2-1.64.0"
SAN_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

mkdir -p "$ROOT"
export PKG_CONFIG_PATH="$NG_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
test -f "$NG_PREFIX/lib/pkgconfig/libnghttp2.pc" || exit 1

for v in 2.4.68 2.4.69; do
  PREFIX="$ROOT/install-$v-asan"
  if [ -f "$PREFIX/bin/httpd" ]; then echo "== $v already built =="; continue; fi
  echo "== building httpd $v (ASan/UBSan, event MPM, http2) =="
  rm -rf "$ROOT/httpd-$v"
  tar xf "$SRC/httpd-$v.tar.bz2" -C "$ROOT"
  cd "$ROOT/httpd-$v" || exit 1
  CC=gcc CFLAGS="$SAN_FLAGS" CXXFLAGS="$SAN_FLAGS" LDFLAGS="-fsanitize=address,undefined" \
    ./configure --prefix="$PREFIX" \
      --with-mpm=event --enable-http2 --with-nghttp2="$NG_PREFIX" \
      --enable-cgi --enable-info --enable-so \
      > "$ROOT/configure-$v.log" 2>&1
  make -j4 > "$ROOT/make-$v.log" 2>&1
  make install > "$ROOT/install-$v.log" 2>&1
  echo "== built $v -> $PREFIX/bin/httpd =="
done
echo "L3 BUILDS DONE"
