#!/bin/sh
# Build all three harness configurations from the pinned tarballs, then replay.
# Run from the repo root (or the lab dir) in a clean archived checkout.
set -eu
cd "$(dirname "$0")"
COMMON='--disable-shared --enable-static --without-magick-plus-plus --without-x --without-perl --without-fontconfig --without-freetype --without-jpeg --without-png --without-tiff --without-webp --without-xml --without-zlib --without-bzlib --without-lzma --without-openjp2 --without-heic --without-raw --without-openexr --without-djvu --without-dps --without-gslib --without-gvc --without-lcms --without-pango --without-raqm --without-jbig --without-wmf --without-flif --without-fftw --disable-openmp'
ASAN_FLAGS='-g -O1 -fsanitize=address -fno-omit-frame-pointer'

[ -d vuln/MagickCore ] || { mkdir -p vuln; tar xzf ImageMagick-7.1.2-34.tar.gz -C vuln --strip-components=1; }
[ -d fixed/MagickCore ] || { mkdir -p fixed; tar xzf ImageMagick-7.1.2-35.tar.gz -C fixed --strip-components=1; }
[ -d plain-src/MagickCore ] || { mkdir -p plain-src; tar xzf ImageMagick-7.1.2-34.tar.gz -C plain-src --strip-components=1; }

[ -f vuln/Makefile ] || (cd vuln && ./configure $COMMON CFLAGS="$ASAN_FLAGS" CXXFLAGS="$ASAN_FLAGS" LDFLAGS='-fsanitize=address' > configure.log 2>&1 && make -j2 > build.log 2>&1)
[ -f fixed-build/Makefile ] || { mkdir -p fixed-build; (cd fixed-build && ../fixed/configure $COMMON CFLAGS="$ASAN_FLAGS" CXXFLAGS="$ASAN_FLAGS" LDFLAGS='-fsanitize=address' > configure.log 2>&1 && make -j2 > build.log 2>&1); }
[ -f plain-build/Makefile ] || { mkdir -p plain-build; (cd plain-build && ../plain-src/configure $COMMON CFLAGS='-g -O0' CXXFLAGS='-g -O0' > configure.log 2>&1 && make -j2 > build.log 2>&1); }

sh run-all.sh
