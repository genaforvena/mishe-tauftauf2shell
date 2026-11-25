#!/bin/sh
# Plain (no sanitizer) real GPGME build for the CVE-2026-129975 reuse path.
# Uses the tarballs and source trees provisioned by build-real.sh; builds a
# separate prefix so no ASan-instrumented static library is linked in.
set -eu
cd "$(dirname "$0")"
HERE=$PWD
PREFIX=$HERE/prefix-plain
mkdir -p src evidence

for tree in libgpg-error-1.50 libassuan-2.5.7 gpgme-2.2.0 gpgme-fixed; do
  [ -d "$tree" ] || { echo "FAIL: missing $tree; run build-real.sh first" >&2; exit 2; }
done

CF='-g -O0'
BASE="--enable-static --disable-shared --with-libgpg-error-prefix=$PREFIX --with-libassuan-prefix=$PREFIX"

[ -d err-plain-build ] || mkdir err-plain-build
[ -f err-plain-build/Makefile ] || (cd err-plain-build && CFLAGS="$CF" \
  ../libgpg-error-1.50/configure --prefix="$PREFIX" --enable-static --disable-shared CC=clang)
make -C err-plain-build -j2 >/dev/null 2>&1
make -C err-plain-build install >/dev/null 2>&1

[ -d assuan-plain-build ] || mkdir assuan-plain-build
[ -f assuan-plain-build/Makefile ] || (cd assuan-plain-build && CFLAGS="$CF" \
  ../libassuan-2.5.7/configure --prefix="$PREFIX" --enable-static --disable-shared \
  --with-libgpg-error-prefix="$PREFIX" CC=clang)
make -C assuan-plain-build -j2 >/dev/null 2>&1
make -C assuan-plain-build install >/dev/null 2>&1

for pair in gpgme-plain-build:gpgme-2.2.0 gpgme-plain-fixed-build:gpgme-fixed; do
  build=${pair%%:*}; tree=${pair##*:}
  [ -d "$build" ] || mkdir "$build"
  if [ ! -f "$build/Makefile" ]; then
    (cd "$build" && PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" CFLAGS="$CF" \
      ../"$tree"/configure --prefix="$PREFIX" $BASE CC=clang)
  fi
  # As in build-real.sh, the tests directory fails to link with static libs;
  # the static library is complete before that point.
  make -C "$build" -j2 >"$build/build.log" 2>&1 || true
  [ -f "$build/src/.libs/libgpgme.a" ] || { echo "FAIL: no lib in $build" >&2; exit 2; }
done

link_driver() {
  out=$1; build=$2
  clang -g -O0 -I "$build/src" -I "$PREFIX/include" -o "$out" status_reuse.c \
    "$build/src/.libs/libgpgme.a" "$PREFIX/lib/libassuan.a" \
    "$PREFIX/lib/libgpg-error.a" -lpthread -ldl
}
link_driver status-reuse-plain-vuln gpgme-plain-build
link_driver status-reuse-plain-fixed gpgme-plain-fixed-build

link_groom_driver() {
  out=$1; build=$2
  clang -g -O0 -I "$build/src" -I "$PREFIX/include" -o "$out" status_groom.c \
    "$build/src/.libs/libgpgme.a" "$PREFIX/lib/libassuan.a" \
    "$PREFIX/lib/libgpg-error.a" -lpthread -ldl
}
link_groom_driver status-groom-plain-vuln gpgme-plain-build
link_groom_driver status-groom-plain-fixed gpgme-plain-fixed-build
echo "BUILD PLAIN OK"
