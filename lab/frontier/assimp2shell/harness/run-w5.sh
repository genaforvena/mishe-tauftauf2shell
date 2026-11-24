#!/usr/bin/env bash
# W5: larger declared-vs-actual accessor mismatch on the real importer path.
# MAT4/FLOAT has elemSize=64 in the pinned v6.0.6 glTF 1.0 parser; POSITION
# targets a 12-byte aiVector3D and indices target a 4-byte uint32_t local.
# Both cases are author-measured, unwitnessed; the PR6860 hunk is an open,
# unmerged proposed fix, never a released fixed version.
set -euo pipefail
cd "$(dirname "$0")/.."

bash bootstrap.sh >/dev/null
mkdir -p w5/evidence harness/bin
rm -f w5/evidence/*.out
log=w5/evidence/w5.log
: >"$log"
pass=0
fail=0

check() { # name, logfile, required substring (or empty), rejected substring (or empty)
    local name="$1" file="$2" need="${3-}" reject="${4-}"
    if [ -n "$need" ] && ! grep -qF "$need" "$file"; then
        printf 'FAIL %s (missing: %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    if [ -n "$reject" ] && grep -qF "$reject" "$file"; then
        printf 'FAIL %s (found: %s)\n' "$name" "$reject" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

build_asan_driver() { # source tree, build dir, output driver
    local src="$1" bld="$2" out="$3"
    if [ ! -f "$bld/bin/libassimp.so.6.0.6" ]; then
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
    fi
    g++ -O1 -g0 -fsanitize=address -fno-omit-frame-pointer \
        -I "$src/include" -I "$bld/include" \
        harness/real_driver.cpp -L "$bld/bin" -lassimp \
        -Wl,-rpath,"$PWD/$bld/bin" -o "$out"
}

src=pins/assimp-6.0.6
fixed_src=pins/fixed-full-6.0.6
if [ ! -f "$fixed_src/code/AssetLib/glTF/glTFAsset.inl" ]; then
    rm -rf "$fixed_src"
    cp -a "$src" "$fixed_src"
    cp pins/fixed-6.0.6/code/AssetLib/glTF/glTFAsset.inl \
        "$fixed_src/code/AssetLib/glTF/glTFAsset.inl"
    patch -d "$fixed_src" -p0 < pins/pr6860-gltfAsset.h-decl.patch
fi
build_asan_driver "$src" build-min harness/bin/w5_real_vuln
build_asan_driver "$fixed_src" build-min-fixed harness/bin/w5_real_fixed

for pair in vuln:build-min fixed:build-min-fixed; do
    label=${pair%%:*}
    lib=${pair##*:}
    g++ -O1 -g0 -fsanitize=address -fno-omit-frame-pointer \
        -I "$src/include" -I "$lib/include" \
        harness/w5_driver.cpp -L "$lib/bin" -lassimp \
        -Wl,-rpath,"$PWD/$lib/bin" -o "harness/bin/w5_cb_$label"
done


if [ ! -f build-min-plain/bin/libassimp.so.6.0.6 ]; then
    cmake -G Ninja -S "$src" -B build-min-plain \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS='-O1 -g0' \
        -DCMAKE_CXX_FLAGS='-O1 -g0' \
        -DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_GLTF_IMPORTER=ON \
        -DASSIMP_BUILD_ALL_EXPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_ASSIMP_TOOLS=OFF \
        -DASSIMP_BUILD_TESTS=OFF \
        -DASSIMP_BUILD_SAMPLES=OFF \
        -DASSIMP_BUILD_ZLIB=ON \
        -DASSIMP_WARNINGS_AS_ERRORS=OFF >/dev/null
    cmake --build build-min-plain --parallel 2 --target assimp >/dev/null
fi
if [ ! -f harness/bin/w5_plain ]; then
    g++ -O1 -g0 -DPLAIN_READ \
        -I "$src/include" -I build-min-plain/include \
        harness/placement_driver.cpp -L build-min-plain/bin -lassimp \
        -Wl,-rpath,"$PWD/build-min-plain/bin" -o harness/bin/w5_plain
fi

run() { # driver, case, output, mode (asan|cb|plain)
    local drv="$1" c="$2" out="$3" mode="$4" rc=0
    case "$mode" in
        plain) "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
        cb) ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=0:symbolize=1 \
            "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
        *) ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 \
            "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$? ;;
    esac
    printf '# %s case=%s mode=%s rc=%s\n' "$(basename "$drv")" "$c" "$mode" "$rc" >>"$log"
}

run harness/bin/w5_real_vuln mat4pos-count1 w5/evidence/mat4pos-vuln.out asan
check mat4pos-write64 w5/evidence/mat4pos-vuln.out 'WRITE of size 64'
check mat4pos-region12 w5/evidence/mat4pos-vuln.out '0 bytes after 12-byte region'
check mat4pos-frame w5/evidence/mat4pos-vuln.out 'in Assimp::glTFImporter::ImportMeshes(glTF::Asset&)'

run harness/bin/w5_real_fixed mat4pos-count1 w5/evidence/mat4pos-fixed.out asan
check mat4pos-fixed-clean w5/evidence/mat4pos-fixed.out 'scene=ok' 'ERROR: AddressSanitizer'

run harness/bin/w5_cb_vuln mat4pos-count1 w5/evidence/chosen-vuln.out cb
check mat4pos-chosen-bytes w5/evidence/chosen-vuln.out 'at80=54415546'
check mat4pos-import-completed w5/evidence/chosen-vuln.out 'scene=ok'

run harness/bin/w5_cb_fixed mat4pos-count1 w5/evidence/chosen-fixed.out cb
check mat4pos-cb-fixed-clean w5/evidence/chosen-fixed.out 'scene=ok' 'POST_WRITE'

run harness/bin/w5_plain mat4pos-count1 w5/evidence/mat4pos-plain.out plain
check mat4pos-plain-abort w5/evidence/mat4pos-plain.out 'malloc(): invalid size (unsorted)'

run harness/bin/w5_real_vuln mat4idx-count1 w5/evidence/mat4idx-vuln.out asan
check mat4idx-stack-write64 w5/evidence/mat4idx-vuln.out 'stack-buffer-overflow'
check mat4idx-write64 w5/evidence/mat4idx-vuln.out 'WRITE of size 64'
check mat4idx-value-frame w5/evidence/mat4idx-vuln.out "'value' <== Memory access"

run harness/bin/w5_real_fixed mat4idx-count1 w5/evidence/mat4idx-fixed.out asan
check mat4idx-fixed-still-fails w5/evidence/mat4idx-fixed.out '*** buffer overflow detected ***'

run harness/bin/w5_real_vuln safe w5/evidence/safe.out asan
check safe-clean w5/evidence/safe.out 'scene=ok' 'ERROR: AddressSanitizer'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
sha256sum w5/evidence/*.out | tee -a "$log"
[ "$fail" -eq 0 ]
