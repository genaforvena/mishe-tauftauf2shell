#!/usr/bin/env bash
# W9: PR7090 (the second referenced, open/unmerged fix) as a proposed-hunk
# control. The hunk rejects non-scalar index accessors and mismatched NORMAL
# counts in ImportMeshes; it does not touch Accessor::ExtractData. Measured
# through the public Importer::ReadFileFromMemory path with ASan.
# Prerequisite: bash harness/run-w5.sh once (builds the pinned vulnerable
# libraries/drivers reused for the baseline comparison).
set -euo pipefail
cd "$(dirname "$0")/.."

for drv in harness/bin/w5_real_vuln; do
    if [ ! -x "$drv" ]; then
        echo "missing $drv: run 'bash harness/run-w5.sh' first" >&2
        exit 2
    fi
done

sha256sum -c PINS.sha256 >/dev/null

src=pins/assimp-6.0.6
fix=pins/fixed7090-6.0.6
bld=build-min-7090
drv=harness/bin/w9_real_7090
if [ ! -f "$fix/code/AssetLib/glTF/glTFImporter.cpp" ]; then
    rm -rf "$fix"
    cp -a "$src" "$fix"
    patch -d "$fix" -p0 code/AssetLib/glTF/glTFImporter.cpp < pins/pr7090-gltfImporter.patch
fi
if [ ! -f "$bld/bin/libassimp.so.6.0.6" ]; then
    cmake -G Ninja -S "$fix" -B "$bld" \
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
if [ ! -x "$drv" ]; then
    g++ -O1 -g0 -fsanitize=address -fno-omit-frame-pointer \
        -I "$fix/include" -I "$bld/include" \
        harness/real_driver.cpp -L "$bld/bin" -lassimp \
        -Wl,-rpath,"$PWD/$bld/bin" -o "$drv"
fi

mkdir -p w9/evidence
rm -f w9/evidence/*.out
log=w9/evidence/w9.log
: >"$log"
pass=0
fail=0

check() { # name, logfile, required substring, rejected substring (or empty)
    local name="$1" file="$2" need="$3" reject="${4-}"
    if ! grep -qF "$need" "$file"; then
        printf 'FAIL %s (missing: %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    if [ -n "$reject" ] && grep -qF "$reject" "$file"; then
        printf 'FAIL %s (found: %s)\n' "$name" "$reject" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

run() { # driver, case, mode
    local drv="$1" c="$2" mode="$3" rc=0
    local out="w9/evidence/$c-$mode.out"
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:symbolize=1 \
        "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$?
    printf '# %s case=%s mode=%s rc=%s\n' "$(basename "$drv")" "$c" "$mode" "$rc" >>"$log"
}

# Preserved baselines: the unpatched pinned library still faults on all three
# ExtractData sites and the two non-scalar index cases.
for c in vec4pos mat4pos-count1 mat4norm-count1 mat4tex-count1 idx3 mat4idx-count1; do
    run harness/bin/w5_real_vuln "$c" vuln
done
check baseline-vec4pos w9/evidence/vec4pos-vuln.out 'WRITE of size 16'
check baseline-vec4pos-asan w9/evidence/vec4pos-vuln.out 'ERROR: AddressSanitizer'
check baseline-mat4pos w9/evidence/mat4pos-count1-vuln.out 'WRITE of size 64'
check baseline-mat4norm w9/evidence/mat4norm-count1-vuln.out 'WRITE of size 64'
check baseline-mat4tex w9/evidence/mat4tex-count1-vuln.out 'WRITE of size 64'
check baseline-idx3 w9/evidence/idx3-vuln.out 'stack-buffer-overflow'
check baseline-mat4idx w9/evidence/mat4idx-count1-vuln.out 'stack-buffer-overflow'

# PR7090 overlay: non-scalar indices are rejected before Indexer::GetValue.
for c in idx3 mat4idx-count1; do
    run "$drv" "$c" fixed7090
done
for c in idx3 mat4idx-count1; do
    check "$c-fixed7090-reject" "w9/evidence/$c-fixed7090.out" 'not scalars of unsigned integers'
    check "$c-fixed7090-no-asan" "w9/evidence/$c-fixed7090.out" 'scene=null' 'ERROR: AddressSanitizer'
done

# PR7090 does not add the missing element-size check: ExtractData lanes still
# fault, and the distinct TEXCOORD count mismatch still reads out of bounds.
for c in vec4pos mat4pos-count1 mat4norm-count1 mat4tex-count1 texcount-mismatch; do
    run "$drv" "$c" fixed7090
done
check fixed7090-vec4pos-still-oob w9/evidence/vec4pos-fixed7090.out 'WRITE of size 16'
check fixed7090-mat4pos-still-oob w9/evidence/mat4pos-count1-fixed7090.out 'WRITE of size 64'
check fixed7090-mat4norm-still-oob w9/evidence/mat4norm-count1-fixed7090.out 'WRITE of size 64'
check fixed7090-mat4tex-still-oob w9/evidence/mat4tex-count1-fixed7090.out 'WRITE of size 64'
check fixed7090-texcount-still-read w9/evidence/texcount-mismatch-fixed7090.out 'READ of size 4'
for c in vec4pos mat4pos-count1 mat4norm-count1 mat4tex-count1 texcount-mismatch; do
    check "fixed7090-$c-asan" "w9/evidence/$c-fixed7090.out" 'ERROR: AddressSanitizer'
done

# Safe-input control must stay clean on the overlay build.
run "$drv" safe fixed7090
check fixed7090-safe-clean w9/evidence/safe-fixed7090.out 'scene=ok' 'ERROR: AddressSanitizer'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
sha256sum w9/evidence/*.out | tee -a "$log"
[ "$fail" -eq 0 ]
