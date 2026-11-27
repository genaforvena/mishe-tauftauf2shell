#!/bin/sh
# Build both pinned AFFLIB releases twice: GCC ASan and plain.
# Source tarballs and the fix patch are read-only pinned provisioning.
set -eu
cd "$(dirname "$0")"

(cd pins && sha256sum -c SHA256SUMS >/dev/null)

build_tree() {
    tag="$1" tar="$2" dir="$3" mode="$4"
    if [ ! -d "$dir" ]; then
        tar xzf "pins/$tar"
        case "$tag" in
            vuln) mv AFFLIBv3-3.7.22 "$dir" ;;
            fixed) mv AFFLIBv3-3.7.23 "$dir" ;;
        esac
    fi
    if [ ! -f "$dir/configure" ]; then
        (cd "$dir" && sh bootstrap.sh >/dev/null)
    fi
    if [ ! -f "$dir/lib/.libs/libafflib.a" ]; then
        if [ "$mode" = asan ]; then
            san='-fsanitize=address -g -O1 -fno-omit-frame-pointer'
        else
            san='-g -O1'
        fi
        (cd "$dir" && ./configure --disable-shared --enable-static \
            CFLAGS="$san" CXXFLAGS="$san" >/dev/null && \
            make -C lib -j2 >/dev/null)
    fi
}

build_tree vuln vuln.tar.gz src-vuln asan
build_tree fixed fixed.tar.gz src-fixed asan
build_tree vuln vuln.tar.gz plain-vuln plain
build_tree fixed fixed.tar.gz plain-fixed plain

compile_harness() {
    src="$1" out="$2" san="$3"
    g++ $san -g -O1 -fno-omit-frame-pointer \
        -I"$src" -I"$src/include/afflib" \
        -I"$src/lzma443/C" -I"$src/lzma443/C/7zip/Compress/LZMA_Alone" \
        harness.cpp "$src/lib/.libs/libafflib.a" \
        -lmd -lcrypto -lcurl -lexpat -lrt -lz -lreadline -llzma -pthread \
        -o "$out"
}

compile_harness src-vuln harness-vuln -fsanitize=address
compile_harness src-fixed harness-fixed -fsanitize=address
compile_harness plain-vuln harness-plain-vuln ''
compile_harness plain-fixed harness-plain-fixed ''
echo BUILD_OK
