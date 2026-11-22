#!/usr/bin/env bash
# libyang2shell: real lyd_parse_data_mem(..., LYD_LYB, ...) reproduction.
#
# Builds the two pinned libyang trees with ASan (if not already built), compiles
# the driver, generates a valid non-shrink LYB blob, and runs six cases:
# vulnerable/hardened x {valid, value-length patch, module-name-length patch}.
# No sockets; no external target contacted at run time.
set -u
cd "$(dirname "$0")" || exit 2
mkdir -p evidence

VSRC=../src/libyang
HSRC=../src/libyang-hardened
VLY="$VSRC/build-asan"
HLY="$HSRC/build-asan"

build_libyang() {
    local src="$1" b="$2"
    [ -f "$b/libyang.so" ] && return 0
    cmake -S "$src" -B "$b" -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTS=OFF \
        -DENABLE_VALGRIND_TESTS=OFF \
        -DCMAKE_C_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1' \
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' >/dev/null 2>&1 || return 1
    cmake --build "$b" -j4 >/dev/null 2>&1 || return 1
}

build_libyang "$VSRC" "$VLY" || { echo 'vulnerable build FAILED'; exit 3; }
build_libyang "$HSRC" "$HLY" || { echo 'hardened build FAILED'; exit 3; }

CCFLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1'
gcc $CCFLAGS -I"$VLY" -I"$VLY/libyang" -I"$VSRC/src" lyb_driver.c \
    -L"$VLY" -lyang -Wl,-rpath,"$PWD/$VLY" -o lyb_driver || exit 4
gcc $CCFLAGS -I"$HLY" -I"$HLY/libyang" -I"$HSRC/src" lyb_driver.c \
    -L"$HLY" -lyang -Wl,-rpath,"$PWD/$HLY" -o lyb_driver-hardened || exit 4

export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
./lyb_driver gen valid.lyb > evidence/gen.txt 2>&1 || exit 5

run_case() {
    local label="$1" bin="$2" mode="$3" e=0
    {
        printf '=== %s %s ===\n' "$label" "$mode"
        if [ "$label" = hardened ]; then
            LY_TEST_SEARCHDIR="$PWD/$HSRC/modules" "$bin" parse valid.lyb "$mode" 2>&1
        else
            "$bin" parse valid.lyb "$mode" 2>&1
        fi
        e=$?
        printf 'EXIT=%d\n' "$e"
    } > "evidence/$label-$mode.txt"
    printf '%s %s: ' "$label" "$mode"
    grep -m1 -E 'ERROR: AddressSanitizer|LYB string length overflow|^RC=' "evidence/$label-$mode.txt" || true
}

run_case vulnerable ./lyb_driver none
run_case vulnerable ./lyb_driver patch
run_case vulnerable ./lyb_driver patchmod
run_case hardened ./lyb_driver-hardened none
run_case hardened ./lyb_driver-hardened patch
run_case hardened ./lyb_driver-hardened patchmod

echo '--- frame lines (vulnerable patchmod) ---'
grep -E '#[0-9]+ .*(lyb_read_string|lyb_parse_module|lyd_parse_data_mem|ly_in_read|lyb_read )' \
    evidence/vulnerable-patchmod.txt | sed -E 's/0x[0-9a-f]+/0xADDR/g; s#/[^ ]+\.(c|inc):[0-9]+#PATH:LINE#g' | head -12
echo DONE
