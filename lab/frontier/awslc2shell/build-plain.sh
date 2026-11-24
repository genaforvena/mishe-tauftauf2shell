#!/bin/sh
# Build non-ASan AWS-LC libraries plus the metadata probe, from pinned sources.
# Plain builds are needed because ASan poisons the 9 bytes of glibc malloc
# slack the CVE byte actually lands in; an ASan build reports a redzone hit
# instead of the plain-process allocator layout.
set -eu
cd "$(dirname "$0")"

FLAGS='-fno-omit-frame-pointer -g -O0'
for pair in 'src build-plain metadata-vuln' 'src-fixed build-fixed-plain metadata-fixed'; do
  set -- $pair
  srcdir=$1
  builddir=$2
  binary=$3
  cmake -S "$srcdir" -B "$builddir" \
    -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=OFF -DDISABLE_GO=ON \
    -DDISABLE_PERL=ON -DBUILD_SHARED_LIBS=OFF -DCMAKE_C_FLAGS="$FLAGS" \
    > "cmake-$builddir.log" 2>&1
  cmake --build "$builddir" --target crypto -j2 > "build-$builddir.log" 2>&1
  incdir=$srcdir/include
  cc -O0 -g -Wall -Wextra -I "$incdir" metadata.c \
    "$builddir/crypto/libcrypto.a" -lpthread -ldl -o "$binary"
done
echo 'plain builds ready: metadata-vuln metadata-fixed'
