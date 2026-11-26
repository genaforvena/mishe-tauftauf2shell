#!/usr/bin/env bash
# Provision and build both pinned pjproject trees for the real-consumer replay.
# Fetching upstream tarballs is provisioning; no probe leaves this host.
set -euo pipefail
cd "$(dirname "$0")/.."

VULN_SHA=c1ea7648fb53f945493972a23133b9e0d3e4a1fe
FIXED_SHA=7ecc6584969a923c4190b6912afbf5952b5a4b9f
VULN_DIR=pjproject-$VULN_SHA
FIXED_DIR=pjproject-$FIXED_SHA
FLAGS='-fsanitize=address -g -O0 -fno-omit-frame-pointer -DPJMEDIA_HAS_VIDEO=1 -DNDEBUG'
CONFIGURE_ARGS=(--disable-sound --disable-ffmpeg --disable-sdl --disable-ssl
                --disable-v4l2 --without-external-pa)

mkdir -p src/full build-vuln build-fixed

fetch() {
    sha=$1; dir=$2; tarball=$3
    if [ ! -d "src/full/$dir" ]; then
        curl -fsSL --max-time 300 -o "src/full/$tarball" \
            "https://codeload.github.com/pjsip/pjproject/tar.gz/$sha"
        tar -xzf "src/full/$tarball" -C src/full
    fi
    echo "FETCH $dir $(sha256sum "src/full/$tarball" | cut -d' ' -f1)"
}

build_tree() {
    name=$1; dir=$2
    cd "src/full/$dir"
    CFLAGS="$FLAGS" CXXFLAGS="$FLAGS" LDFLAGS='-fsanitize=address' \
        ./configure "${CONFIGURE_ARGS[@]}" > "../../../build-$name/configure-release.log" 2>&1
    make -j6 dep > "../../../build-$name/dep-release.log" 2>&1
    make -j6 > "../../../build-$name/build-release.log" 2>&1
    cd ../../..
    count=$(grep -c avi_get_frame <(nm -C "src/full/$dir/pjmedia/lib/libpjmedia-x86_64-pc-linux-gnu.a") || true)
    echo "BUILD $name rc=0 avi_get_frame_symbols=$count"
}

fetch "$VULN_SHA" "$VULN_DIR" vuln.tar.gz
fetch "$FIXED_SHA" "$FIXED_DIR" fixed.tar.gz
build_tree vuln "$VULN_DIR"
build_tree fixed "$FIXED_DIR"
echo "PROVISION_DONE"
