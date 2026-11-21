#!/usr/bin/env bash
# Reproducible ASan/UBSan build for adjacent lane L5
# (CVE-2026-56449, mod_proxy_html dump_content OOB write on crafted
# response bodies). 2.4.68 affected; 2.4.69 control (dump_content call
# removed from pcomment). System libxml2 2.9.14 is used uninstrumented;
# the suspect code is in instrumented mod_proxy_html.c.
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
ROOT="$HERE/l5"
SRC="$REPO/lab/src"
SAN_FLAGS="-O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer"

mkdir -p "$ROOT"
xml2-config --version >/dev/null 2>&1 || { echo "libxml2 dev missing" >&2; exit 1; }

for v in 2.4.68 2.4.69; do
  PREFIX="$ROOT/install-$v-asan"
  if [ -x "$PREFIX/bin/httpd" ] || [ -x "$PREFIX/sbin/httpd" ]; then
    echo "== $v already built =="; continue
  fi
  echo "== building httpd $v (ASan/UBSan, event MPM, proxy-html) =="
  rm -rf "$ROOT/httpd-$v"
  tar xf "$SRC/httpd-$v.tar.bz2" -C "$ROOT" || exit 1
  cd "$ROOT/httpd-$v" || exit 1
  CC=gcc CFLAGS="$SAN_FLAGS" CXXFLAGS="$SAN_FLAGS" LDFLAGS="-fsanitize=address,undefined" \
    ./configure --prefix="$PREFIX" \
      --with-mpm=event --enable-proxy-html --with-libxml2=/usr \
      --enable-cgi --enable-info --enable-so \
      > "$ROOT/configure-$v.log" 2>&1
  make -j4 > "$ROOT/make-$v.log" 2>&1 || { echo "make $v FAILED"; exit 1; }
  make install > "$ROOT/install-$v.log" 2>&1 || { echo "install $v FAILED"; exit 1; }
  echo "== built $v -> $PREFIX =="
done
echo "L5 BUILDS DONE"
