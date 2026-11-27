#!/bin/sh
# Eight consumers: vulnerable/fixed x ASan/plain x stock-assert/assert-disabled.
# Offline: no network I/O; source archives supply every library byte.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
PINS="$ROOT/pins"
WORK="$ROOT/work"
RUNS="$ROOT/runs"
VULN=9816acc93cfcf071d6ca952fc5b3a266dcded9ce
FIX=252ec0208eb9a0d077afcc53351fca99e2efe81f
mkdir -p "$WORK" "$RUNS"

prepare() {
    kind=$1; sha=$2
    src="$WORK/libstrophe-$sha"
    if [ ! -f "$src/src/scram.c" ]; then
        rm -rf "$src"
        tar xzf "$PINS/libstrophe-$kind.tar.gz" -C "$WORK"
        [ -d "$src" ] || { echo "unexpected archive layout" >&2; exit 2; }
    fi
    if [ ! -x "$src/configure" ]; then
        (cd "$src" && sh bootstrap.sh) >"$WORK/bootstrap-$kind.log" 2>&1
    fi
}

build_one() {
    kind=$1; mode=$2; sha=$3
    src="$WORK/libstrophe-$sha"
    bd="$WORK/build-$kind-$mode"
    if [ "$mode" = asan ] || [ "$mode" = noassert-asan ]; then
        flags="-g -O0 -DNDEBUG -fsanitize=address -fno-omit-frame-pointer -fno-stack-protector"
        ldflags="-fsanitize=address"
    else
        flags="-g -O0 -DNDEBUG -fno-omit-frame-pointer -fno-stack-protector -fno-pie"
        ldflags="-no-pie"
    fi
    extra=""
    case "$mode" in
        noassert-asan|noassert-plain)
            extra=" -include $ROOT/harness/noassert.h"
            ;;
    esac
    flags="$flags$extra"
    mkdir -p "$bd"
    if [ ! -f "$bd/Makefile" ]; then
        (cd "$bd" && "$src/configure" --disable-tls --disable-examples \
            CFLAGS="$flags" LDFLAGS="$ldflags") \
            >"$WORK/configure-$kind-$mode.log" 2>&1
    fi
    (cd "$bd" && make -j2) >"$WORK/make-$kind-$mode.log" 2>&1
    lib="$bd/.libs/libstrophe.a"
    [ -f "$lib" ] || { echo "missing $lib" >&2; exit 2; }
    # shellcheck disable=SC2086
    gcc $flags -I"$src" -I"$src/src" \
        "$ROOT/harness/scram_challenge.c" "$lib" \
        $(pkg-config --libs expat zlib) -lm $ldflags \
        -o "$RUNS/scram-$kind-$mode"
    echo "BUILD_OK $kind $mode $(sha256sum "$RUNS/scram-$kind-$mode" | cut -d' ' -f1)"
}

prepare vuln "$VULN"
prepare fixed "$FIX"
build_one vuln asan "$VULN"
build_one vuln plain "$VULN"
build_one fixed asan "$FIX"
build_one fixed plain "$FIX"
build_one vuln noassert-asan "$VULN"
build_one vuln noassert-plain "$VULN"
build_one fixed noassert-asan "$FIX"
build_one fixed noassert-plain "$FIX"
