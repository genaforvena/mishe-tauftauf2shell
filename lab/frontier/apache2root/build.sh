#!/usr/bin/env bash
# Reproducible ASan/UBSan build of httpd 2.4.70 (affected) and 2.4.71 (fixed)
# for CVE-2026-119618 (mod_http2 assign_headers). Loopback only.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$ROOT/../../.." && pwd)"
SRC="$REPO/lab/src"
NG_VER=1.64.0
NG_PREFIX="$ROOT/deps/nghttp2-$NG_VER"
VERS="2.4.70 2.4.71"
SAN_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

mkdir -p "$ROOT/deps" "$ROOT/logs"

# --- nghttp2 dependency (httpd mod_http2 needs headers + lib) ---
if [ ! -f "$NG_PREFIX/lib/pkgconfig/libnghttp2.pc" ]; then
  echo "== building nghttp2 $NG_VER =="
  rm -rf "$ROOT/nghttp2-$NG_VER"
  tar xf "$SRC/nghttp2-$NG_VER.tar.xz" -C "$ROOT"
  cd "$ROOT/nghttp2-$NG_VER"
  ./configure --prefix="$NG_PREFIX" --disable-shared --enable-static --with-pic \
      --disable-examples --disable-tools --disable-tests > "$ROOT/logs/nghttp2-configure.log" 2>&1
  make -j4 > "$ROOT/logs/nghttp2-make.log" 2>&1
  make install > "$ROOT/logs/nghttp2-install.log" 2>&1
fi
export PKG_CONFIG_PATH="$NG_PREFIX/lib/pkgconfig:${PKG_CONFIG_PATH:-}"

# --- httpd builds ---
for v in $VERS; do
  PREFIX="$ROOT/install-$v-asan"
  [ -f "$PREFIX/bin/httpd" ] && { echo "== $v already built =="; continue; }
  echo "== building httpd $v (ASan/UBSan, event MPM, http2) =="
  rm -rf "$ROOT/httpd-$v"
  tar xf "$SRC/httpd-$v.tar.bz2" -C "$ROOT"
  cd "$ROOT/httpd-$v"
  CC=gcc CFLAGS="$SAN_FLAGS" CXXFLAGS="$SAN_FLAGS" LDFLAGS="-fsanitize=address,undefined" \
    ./configure --prefix="$PREFIX" \
      --with-mpm=event --enable-http2 --with-nghttp2="$NG_PREFIX" \
      --enable-cgi --enable-info --enable-so \
      > "$ROOT/logs/httpd-$v-configure.log" 2>&1
  make -j4 > "$ROOT/logs/httpd-$v-make.log" 2>&1
  make install > "$ROOT/logs/httpd-$v-install.log" 2>&1
  echo "== built $v -> $PREFIX/sbin/httpd =="
done

echo "ALL BUILDS DONE"
