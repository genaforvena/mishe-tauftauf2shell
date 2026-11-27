#!/usr/bin/env bash
# Build both pinned SIPp variants from the release tarballs in pins/.
# asan  -> build-vuln/out-vuln, build-fixed/out-fixed  (cmake -DUSE_ASAN=ON)
# plain -> build-vuln/out-vuln-plain, build-fixed/out-fixed-plain
#          (-O0 -g -fno-stack-protector -D_FORTIFY_SOURCE=0 for marker mechanics)
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
ASAN_FLAGS='-O0 -g -fsanitize=address -fno-sanitize-recover=all -fno-omit-frame-pointer'
PLAIN_FLAGS='-O0 -g -fno-stack-protector -D_FORTIFY_SOURCE=0'

for variant in vuln fixed; do
    case "$variant" in vuln) ver=3.7.7;; fixed) ver=3.7.8;; esac
    for mode in asan plain; do
        src="$ROOT/build-$variant"
        out="$ROOT/out-$variant"
        [[ $mode == plain ]] && out="$ROOT/out-$variant-plain"
        rm -rf -- "$src" "$out"
        mkdir -p -- "$src"
        tar xzf "$ROOT/pins/$variant.tar.gz" -C "$src"
        if [[ $mode == asan ]]; then
            flags=$ASAN_FLAGS
            cmake -S "$src/sipp-$ver" -B "$out" -DCMAKE_BUILD_TYPE=Debug \
                -DUSE_ASAN=ON -DCMAKE_CXX_FLAGS="$flags" -DCMAKE_C_FLAGS="$flags" \
                > "$ROOT/config-$variant.log" 2>&1
        else
            flags=$PLAIN_FLAGS
            cmake -S "$src/sipp-$ver" -B "$out" -DCMAKE_BUILD_TYPE=Debug \
                -DCMAKE_CXX_FLAGS="$flags" -DCMAKE_C_FLAGS="$flags" \
                > "$ROOT/config-$variant-plain.log" 2>&1
        fi
        cmake --build "$out" -j4 > "$ROOT/build-$variant.log" 2>&1
        printf 'BUILD_OK %s-%s\n' "$variant" "$mode"
    done
done
