#!/bin/sh
# Provision and build the real GPGME ASan controls for run-real.sh.
# Fetches four tarballs from gnupg.org (provisioning, no probing), verifies
# their sha256, then builds libgpg-error, libassuan, GPGME 2.2.0, patched
# 2.2.0 and stock 2.3.1, and links the three status-pipe drivers.
set -eu
cd "$(dirname "$0")"
HERE=$PWD
PREFIX=$HERE/prefix
mkdir -p src evidence

fetch() {
  name=$1; url=$2; want=$3
  if [ ! -f "src/$name" ]; then
    curl -fsSL --max-time 180 -o "src/$name" "$url"
  fi
  got=$(sha256sum "src/$name" | cut -d' ' -f1)
  if [ "$got" != "$want" ]; then
    echo "FAIL: sha256 mismatch for $name: $got" >&2
    exit 2
  fi
}

fetch gpgme-2.2.0.tar.bz2 \
  https://gnupg.org/ftp/gcrypt/gpgme/gpgme-2.2.0.tar.bz2 \
  7160e80e84dafd00d956c84891c533bb7ab16a6a54fbe1574b2f3acf0496977b
fetch gpgme-2.3.1.tar.bz2 \
  https://gnupg.org/ftp/gcrypt/gpgme/gpgme-2.3.1.tar.bz2 \
  2bf94e0e677e5a8fc31f79dd323f91c5416b36fb851058bc1e8bce39f2642434
fetch libgpg-error-1.50.tar.bz2 \
  https://gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.50.tar.bz2 \
  69405349e0a633e444a28c5b35ce8f14484684518a508dc48a089992fe93e20a
fetch libassuan-2.5.7.tar.bz2 \
  https://gnupg.org/ftp/gcrypt/libassuan/libassuan-2.5.7.tar.bz2 \
  0103081ffc27838a2e50479153ca105e873d3d65d8a9593282e9c94c7e6afb76

for tree in libgpg-error-1.50 libassuan-2.5.7 gpgme-2.2.0 gpgme-2.3.1; do
  [ -d "$tree" ] || tar xjf "src/$tree.tar.bz2"
done

patched=10179f7853d9284a21af4ad4ab94753654aa40119f9bdef43852e98482b75b08
if [ ! -f gpgme-fixed/src/engine-gpg.c ] ||
   [ "$(sha256sum gpgme-fixed/src/engine-gpg.c | cut -d' ' -f1)" != "$patched" ]; then
  rm -rf gpgme-fixed
  cp -a gpgme-2.2.0 gpgme-fixed
  (cd gpgme-fixed && patch -p1 --forward < "$HERE/../pinned/fix.patch")
fi

FLAGS="CFLAGS=-fsanitize=address -fno-omit-frame-pointer -g -O0"
BASE="--enable-static --disable-shared --with-libgpg-error-prefix=$PREFIX --with-libassuan-prefix=$PREFIX"
[ -d err-build ] || mkdir err-build
[ -f err-build/Makefile ] || (cd err-build && LDFLAGS=-fsanitize=address ../libgpg-error-1.50/configure \
  --prefix="$PREFIX" --enable-static --disable-shared CC=clang $FLAGS)
[ -d assuan-build ] || mkdir assuan-build
[ -f assuan-build/Makefile ] || (cd assuan-build && LDFLAGS=-fsanitize=address ../libassuan-2.5.7/configure \
  --prefix="$PREFIX" --enable-static --disable-shared --with-libgpg-error-prefix="$PREFIX" \
  CC=clang $FLAGS)
for pair in gpgme-asan-build:gpgme-2.2.0 gpgme-fixed-build:gpgme-fixed gpgme-231-build:gpgme-2.3.1; do
  build=${pair%%:*}; tree=${pair##*:}
  [ -d "$build" ] || mkdir "$build"
  if [ ! -f "$build/Makefile" ]; then
    (cd "$build" && PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" LDFLAGS=-fsanitize=address ../"$tree"/configure \
      --prefix="$PREFIX" $BASE CC=clang $FLAGS)
  fi
done

ASAN_OPTIONS=detect_leaks=0 make -C err-build -j2 >/dev/null 2>&1
ASAN_OPTIONS=detect_leaks=0 make -C err-build install >/dev/null 2>&1
ASAN_OPTIONS=detect_leaks=0 make -C assuan-build -j2 >/dev/null 2>&1
ASAN_OPTIONS=detect_leaks=0 make -C assuan-build install >/dev/null 2>&1
for build in gpgme-asan-build gpgme-fixed-build gpgme-231-build; do
  # The tests directory fails to link under this static ASan setup; the
  # static library is complete before that point.
  ASAN_OPTIONS=detect_leaks=0 make -C "$build" -j2 >"$build/build.log" 2>&1 || true
  [ -f "$build/src/.libs/libgpgme.a" ] || { echo "FAIL: no lib in $build" >&2; exit 2; }
done

link_driver() {
  out=$1; build=$2
  clang -fsanitize=address -fno-omit-frame-pointer -g -O0 \
    -I "$build/src" -I "$PREFIX/include" -o "$out" status_trigger.c \
    "$build/src/.libs/libgpgme.a" "$PREFIX/lib/libassuan.a" \
    "$PREFIX/lib/libgpg-error.a" -lpthread -ldl
}
link_driver status-trigger gpgme-asan-build
link_driver status-trigger-fixed gpgme-fixed-build
link_driver status-trigger-231 gpgme-231-build
echo "BUILD OK"
