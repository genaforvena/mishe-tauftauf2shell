#!/usr/bin/env bash
# Provision and build the pinned nfcapd/nfdump pairs used by run-wire.sh.
# Fetches only the two pinned source tarballs from GitHub (no probes); all
# execution is local. Both ASan and plain builds are produced.
set -u
mkdir -p "$(dirname "$0")/src"
cd "$(dirname "$0")/src"

V_SHA=8a00543aa5c7b25b7d3f7642fdf306fd9979f237
F_SHA=32b9cbe7f17e099d59fc5eac71c84c6c6f051fa5
V_TAR_SHA=970247fa1b7deae56ee9ff09ebe8ec5e6c86adef9b5f82c7f2fd67754c29c827
F_TAR_SHA=61c92342d19469a4ee46810953741e48ebc4cce2ad3a5cb369feca2b1dbc81f2

fetch() { # TAG COMMIT TARBALL_SHA
    local tag=$1 sha=$2 want=$3 tarball="nfdump-$1.tar.gz"
    if [ ! -f "$tarball" ]; then
        curl -fsSL --max-time 180 \
            "https://github.com/phaag/nfdump/archive/$sha.tar.gz" -o "$tarball" || exit 2
    fi
    echo "$want  $tarball" | sha256sum -c - >/dev/null || exit 2
    [ -d "nfdump-$sha" ] || tar xzf "$tarball"
}

build_one() { # COMMIT BUILD_DIR asan|plain
    local sha=$1 build=$2 mode=$3 src="nfdump-$1"
    if [ ! -x "$src/configure" ]; then
        (cd "$src" && ./autogen.sh) || exit 2
    fi
    mkdir -p "$build"
    if [ -x "$build/src/nfcapd/nfcapd" ] && [ -x "$build/src/nfdump/nfdump" ]; then
        echo "CACHED $build"
        return
    fi
    local cflags="" ldflags="" devel="--disable-devel"
    if [ "$mode" = asan ]; then
        cflags="-O0 -g -fno-omit-frame-pointer -fsanitize=address"
        ldflags="-fsanitize=address"
        devel="--enable-devel"
    fi
    (cd "$build" && "../$src/configure" "$devel" CFLAGS="$cflags" LDFLAGS="$ldflags") || exit 2
    # VPATH build: generated headers are found first relative to their
    # including source file, so seed both the build and source directories.
    (cd "$build" && make -j4) || true
    cp "$build/src/libnffile/vcs_track.h" "$src/src/libnffile/" 2>/dev/null || true
    cp "$src/src/libnfdump/filter/filter.h" "$build/src/libnfdump/filter/" || exit 2
    cp "$src/src/libnfdump/filter/ipconv.h" "$build/src/libnfdump/filter/" || exit 2
    (cd "$build" && make -j4) || exit 2
    echo "BUILT $build"
}

fetch 8a00543a "$V_SHA" "$V_TAR_SHA"
fetch 32b9cbe7 "$F_SHA" "$F_TAR_SHA"
build_one "$V_SHA" build-vuln-asan asan
build_one "$F_SHA" build-fixed-asan asan
build_one "$V_SHA" build-vuln-plain plain
build_one "$F_SHA" build-fixed-plain plain
for b in build-vuln-asan build-fixed-asan build-vuln-plain build-fixed-plain; do
    [ -x "$b/src/nfcapd/nfcapd" ] && [ -x "$b/src/nfdump/nfdump" ] || exit 2
done
# configure.ac:27-36 appends -fsanitize=address in --enable-devel mode even
# when CFLAGS is empty; assert the built ELF, not the requested flags. Plain
# builds are libtool shell wrappers whose real binary is in .libs/.
has_asan() { # PATH
    local p=$1
    if file "$p" | grep -q 'shell script'; then
        p="$(dirname "$p")/.libs/$(basename "$p")"
    fi
    file "$p" | grep -q 'ELF' || { echo "NOT_ELF $p"; exit 2; }
    nm "$p" 2>/dev/null | grep -q ' __asan_init'
}
for b in build-vuln-asan build-fixed-asan; do
    for x in nfcapd/nfcapd nfdump/nfdump; do
        has_asan "$b/src/$x" || { echo "ASAN_MISSING $b/src/$x"; exit 2; }
    done
done
for b in build-vuln-plain build-fixed-plain; do
    for x in nfcapd/nfcapd nfdump/nfdump; do
        if has_asan "$b/src/$x"; then echo "PLAIN_INSTRUMENTED $b/src/$x"; exit 2; fi
    done
done
echo BUILD_INSTRUMENTATION_OK
echo BUILD_WIRE_OK
