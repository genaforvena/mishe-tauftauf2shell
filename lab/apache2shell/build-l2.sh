#!/usr/bin/env bash
# Reproducible ASan/UBSan build for adjacent lane L2 (CVE-2026-23918,
# mod_http2 double purge on early reset): 2.4.66 affected (mod_h2 2.0.35),
# 2.4.67 control (mod_h2 2.0.39, contains the add_for_purge fix).
# Reuses the pinned loopback-only nghttp2 1.64.0 from apache2root.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ROOT="$HERE/l2"
SRC="$REPO/lab/src"
NG_PREFIX="$REPO/lab/frontier/apache2root/deps/nghttp2-1.64.0"
SAN_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

mkdir -p "$ROOT"
export PKG_CONFIG_PATH="$NG_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
test -f "$NG_PREFIX/lib/pkgconfig/libnghttp2.pc"

for v in 2.4.66 2.4.67; do
  PREFIX="$ROOT/install-$v-asan"
  if [ -f "$PREFIX/sbin/httpd" ]; then echo "== $v already built =="; continue; fi
  echo "== building httpd $v (ASan/UBSan, event MPM, http2) =="
  rm -rf "$ROOT/httpd-$v"
  tar xf "$SRC/httpd-$v.tar.bz2" -C "$ROOT"
  cd "$ROOT/httpd-$v"
  CC=gcc CFLAGS="$SAN_FLAGS" CXXFLAGS="$SAN_FLAGS" LDFLAGS="-fsanitize=address,undefined" \
    ./configure --prefix="$PREFIX" \
      --with-mpm=event --enable-http2 --with-nghttp2="$NG_PREFIX" \
      --enable-cgi --enable-info --enable-so \
      > "$ROOT/configure-$v.log" 2>&1
  make -j4 > "$ROOT/make-$v.log" 2>&1
  make install > "$ROOT/install-$v.log" 2>&1
  echo "== built $v -> $PREFIX/sbin/httpd =="
done
echo "L2 BUILDS DONE"
