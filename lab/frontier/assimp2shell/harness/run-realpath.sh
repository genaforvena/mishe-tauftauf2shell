#!/usr/bin/env bash
# Real import path for CVE-2026-134861: feed the tracked crafted glTF 1.0
# documents to Assimp::Importer::ReadFileFromMemory in a minimal ASan build of
# the pinned v6.0.6 library, and repeat with the proposed PR6860 hunk applied.
# The hunk is a proposed fix, not a released fixed version.
set -euo pipefail
cd "$(dirname "$0")/.."

bash bootstrap.sh >/dev/null
mkdir -p realpath/evidence harness/bin
log=realpath/evidence/realpath.log
: >"$log"
pass=0
fail=0
check() { # name, logfile, fixed substring to require (or empty), ASan-free flag
    local name="$1" file="$2" need="$3" clean="$4"
    if [ -n "$need" ] && ! grep -qF "$need" "$file"; then
        printf 'FAIL %s (missing: %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    if [ "$clean" = yes ] && grep -qF 'ERROR: AddressSanitizer' "$file"; then
        printf 'FAIL %s (unexpected ASan report)\n' "$name" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

build_and_link() { # source tree, build dir, driver binary
    local src="$1" bld="$2" drv="$3"
    cmake -G Ninja -S "$src" -B "$bld" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS='-O1 -g0 -fsanitize=address -fno-omit-frame-pointer' \
        -DCMAKE_CXX_FLAGS='-O1 -g0 -fsanitize=address -fno-omit-frame-pointer' \
        -DCMAKE_EXE_LINKER_FLAGS='-fsanitize=address' \
        -DCMAKE_SHARED_LINKER_FLAGS='-fsanitize=address' \
        -DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_GLTF_IMPORTER=ON \
        -DASSIMP_BUILD_ALL_EXPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_ASSIMP_TOOLS=OFF \
        -DASSIMP_BUILD_TESTS=OFF \
        -DASSIMP_BUILD_SAMPLES=OFF \
        -DASSIMP_BUILD_ZLIB=ON \
        -DASSIMP_WARNINGS_AS_ERRORS=OFF >/dev/null
    cmake --build "$bld" --parallel 2 --target assimp >/dev/null
    g++ -O1 -g0 -fsanitize=address -fno-omit-frame-pointer \
        -I "$src/include" -I "$bld/include" \
        harness/real_driver.cpp -L "$bld/bin" -lassimp \
        -Wl,-rpath,"$PWD/$bld/bin" -o "$drv"
}

run_driver() { # driver, case, output
    local drv="$1" case="$2" out="$3"
    if ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 \
        "$drv" "harness/cases/$case.gltf" >"$out" 2>&1; then rc=0; else rc=$?; fi
    printf '# %s case=%s exit=%s\n' "$(basename "$drv")" "$case" "$rc" >>"$log"
}

build_and_link pins/assimp-6.0.6 build-min harness/bin/real_driver_min
for c in vec4pos idx3 safe; do
    run_driver harness/bin/real_driver_min "$c" "realpath/evidence/$c.out"
done
check vuln-vec4pos-heap-overflow realpath/evidence/vec4pos.out \
    '0 bytes after 36-byte region' no
check vuln-vec4pos-frame realpath/evidence/vec4pos.out \
    'in Assimp::glTFImporter::ImportMeshes(glTF::Asset&)' no
check vuln-idx3-stack-overflow realpath/evidence/idx3.out \
    'overflows this variable' no
check vuln-idx3-frame realpath/evidence/idx3.out \
    'in Assimp::glTFImporter::ImportMeshes(glTF::Asset&)' no
check vuln-safe-clean realpath/evidence/safe.out 'scene=ok' yes

if [ ! -f pins/fixed-full-6.0.6/code/AssetLib/glTF/glTFAsset.inl ]; then
    rm -rf pins/fixed-full-6.0.6
    cp -a pins/assimp-6.0.6 pins/fixed-full-6.0.6
    cp pins/fixed-6.0.6/code/AssetLib/glTF/glTFAsset.inl \
        pins/fixed-full-6.0.6/code/AssetLib/glTF/glTFAsset.inl
    # The proposed PR6860 .inl hunk calls CheckDataRange but does not declare
    # it; this local-only hunk makes the proposed fix buildable as a control.
    patch -d pins/fixed-full-6.0.6 -p0 < pins/pr6860-gltfAsset.h-decl.patch
fi
build_and_link pins/fixed-full-6.0.6 build-min-fixed harness/bin/real_driver_fixed
for c in vec4pos idx3 safe; do
    run_driver harness/bin/real_driver_fixed "$c" "realpath/evidence/fixed-$c.out"
done
check fixed-vec4pos-blocked realpath/evidence/fixed-vec4pos.out 'scene=' yes
check fixed-idx3-still-overflows realpath/evidence/fixed-idx3.out \
    'overflows this variable' no
check fixed-safe-clean realpath/evidence/fixed-safe.out 'scene=ok' yes

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
sha256sum realpath/evidence/*.out | tee -a "$log"
[ "$fail" -eq 0 ]
