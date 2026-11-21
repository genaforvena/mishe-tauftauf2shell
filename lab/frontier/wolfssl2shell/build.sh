#!/usr/bin/env bash
# Build both pinned wolfSSL tarballs verbatim (no library source edits) and
# compile the in-process harness against each real static library.
set -euo pipefail

LAB="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$LAB/src"
TREES="$LAB/build"

if [ "$#" -lt 1 ]; then
    echo "usage: build.sh <absolute-outdir>" >&2
    exit 2
fi
OUT="$1"
case "$OUT" in
    /*) ;;
    *) echo "outdir must be absolute: $OUT" >&2; exit 2 ;;
esac
mkdir -p "$OUT/logs" "$OUT/.state"

# Verify the pinned artifacts before using any of them.
(cd "$SRC" && sha256sum -c SHA256SUMS > "$OUT/logs/sha256sum.log")

CFGS=(--enable-dtls --enable-tls13 --enable-dtls13 --disable-shared
      --enable-static --disable-examples --disable-crypttests)
SAN_CFLAGS="-fsanitize=address -g -O0 -fno-omit-frame-pointer"
SAN_LDFLAGS="-fsanitize=address"

build_one() {
    local ver="$1"
    local tar="$SRC/v${ver}-stable.tar.gz"
    local tree="$TREES/wolfssl-${ver}-stable"
    local stamp="$OUT/.state/${ver}.stamp"
    local lib="$tree/src/.libs/libwolfssl.a"

    mkdir -p "$TREES"
    if [ ! -d "$tree" ]; then
        tar xzf "$tar" -C "$TREES"
    fi

    if [ ! -f "$stamp" ] || [ ! -f "$lib" ] || [ ! -f "$tree/Makefile" ]; then
        (
            cd "$tree"
            if [ ! -x ./configure ]; then
                ./autogen.sh > "$OUT/logs/${ver}-autogen.log" 2>&1
            fi
            ./configure "${CFGS[@]}" \
                CFLAGS="$SAN_CFLAGS" LDFLAGS="$SAN_LDFLAGS" \
                > "$OUT/logs/${ver}-configure.log" 2>&1
            make -j2 > "$OUT/logs/${ver}-make.log" 2>&1
        )
        # Confirm the generated build options really enable DTLS 1.3.
        if ! grep -q '^#define WOLFSSL_DTLS13' "$tree/wolfssl/options.h"; then
            echo "ERROR: WOLFSSL_DTLS13 missing from $tree/wolfssl/options.h" >&2
            exit 1
        fi
        if [ ! -f "$lib" ]; then
            echo "ERROR: $lib missing after build" >&2
            exit 1
        fi
        printf '%s\n' "${CFGS[*]} $SAN_CFLAGS $SAN_LDFLAGS" > "$stamp"
    fi

    gcc -fsanitize=address -g -O0 -fno-omit-frame-pointer \
        -Wno-deprecated-declarations \
        -I"$tree" "$LAB/ack_overflow.c" "$lib" -lm -lpthread \
        -o "$OUT/ack_overflow_v${ver}"

    echo "PASS build_v${ver}_asan"
    echo "PASS build_v${ver}_dtls13_option"
}

build_one 5.9.0
build_one 5.9.1
