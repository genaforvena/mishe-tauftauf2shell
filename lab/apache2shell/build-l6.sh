#!/usr/bin/env bash
# Reproducible ASan/UBSan build for adjacent lane L6
# (CVE-2026-56153, mod_charset_lite finish_partial_char heap overflow).
# 2.4.68 affected; 2.4.69 control (bounds guard on ctx->saved).
# No libxml2/proxy needed: only charset-lite and the core filter modules.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ROOT="$HERE/l6"
SRC="$REPO/lab/src"
SAN_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

mkdir -p "$ROOT"

for v in 2.4.68 2.4.69; do
  PREFIX="$ROOT/install-$v-asan"
  if [ -x "$PREFIX/bin/httpd" ] || [ -x "$PREFIX/sbin/httpd" ]; then
    echo "== $v already built =="; continue
  fi
  echo "== building httpd $v (ASan/UBSan, event MPM, charset-lite) =="
  rm -rf "$ROOT/httpd-$v"
  tar xf "$SRC/httpd-$v.tar.bz2" -C "$ROOT" || exit 1
  cd "$ROOT/httpd-$v" || exit 1
  CC=gcc CFLAGS="$SAN_FLAGS" CXXFLAGS="$SAN_FLAGS" LDFLAGS="-fsanitize=address,undefined" \
    ./configure --prefix="$PREFIX" \
      --with-mpm=event --enable-charset-lite \
      --enable-cgi --enable-info --enable-so \
      > "$ROOT/configure-$v.log" 2>&1
  make -j4 > "$ROOT/make-$v.log" 2>&1 || { echo "make $v FAILED"; exit 1; }
  make install > "$ROOT/install-$v.log" 2>&1 || { echo "install $v FAILED"; exit 1; }
  grep -q 'mod_charset_lite' "$PREFIX/build/config.nice" 2>/dev/null || true
  echo "== built $v -> $PREFIX =="
done
echo "L6 BUILDS DONE"
