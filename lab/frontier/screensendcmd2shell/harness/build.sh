#!/bin/sh
# Reproduce the GNU Screen 5.0.1/5.0.2 builds used by run-all.sh.
set -eu
cd "$(dirname "$0")/.."
sha256sum -c SHA256SUMS >/dev/null

arm_build() {
    arm=$1 tarball=$2 cflags=$3 ldflags=$4
    dir="build-$arm"
    rm -rf "$dir"
    mkdir -p "$dir"
    tar xzf "src/$tarball" -C "$dir" --strip-components=1
    echo "CONFIGURE $arm"
    (cd "$dir" && ./configure CFLAGS="$cflags" LDFLAGS="$ldflags" > configure.log 2>&1)
    echo "BUILD $arm"
    (cd "$dir" && make -j4 > build.log 2>&1)
    test -x "$dir/screen"
}

asan='-O1 -g -fsanitize=address -fno-omit-frame-pointer'
asanld='-fsanitize=address'
arm_build vuln-asan screen-5.0.1.tar.gz "$asan" "$asanld"
arm_build fixed-asan screen-5.0.2.tar.gz "$asan" "$asanld"
arm_build vuln-asanrec screen-5.0.1.tar.gz \
  '-O1 -g -fsanitize=address -fsanitize-recover=address -fno-omit-frame-pointer' \
  '-fsanitize=address -fsanitize-recover=address'
echo BUILD_OK
