#!/usr/bin/env bash
# Rebuild both pinned tcpreplay variants from the tarballs in pins/.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ASAN_FLAGS='-O0 -g -fno-omit-frame-pointer -fsanitize=address -fno-sanitize-recover=all'
PLAIN_FLAGS='-O0 -g -fno-stack-protector -D_FORTIFY_SOURCE=0'

for variant in vuln fixed; do
    src="$ROOT/src-$variant"
    rm -rf -- "$src"
    mkdir -p -- "$src"
    tar xzf "$ROOT/pins/$variant.tar.gz" -C "$src"

    for mode in asan plain; do
        build="$ROOT/build-$variant-$mode"
        rm -rf -- "$build"
        if [[ $mode == asan ]]; then
            flags=$ASAN_FLAGS
            link='-fsanitize=address'
        else
            flags=$PLAIN_FLAGS
            link=''
        fi
        cmake -S "$src" -B "$build" \
            -DPYTHON3_EXECUTABLE=/usr/bin/python3 \
            -DCMAKE_C_FLAGS="$flags" \
            -DCMAKE_EXE_LINKER_FLAGS="$link" \
            > "$ROOT/build-$variant-$mode-cmake.log" 2>&1
        cmake --build "$build" --target tcpprep -j4 \
            > "$ROOT/build-$variant-$mode.log" 2>&1
        printf 'BUILD_OK %s-%s\n' "$variant" "$mode"
    done
done
