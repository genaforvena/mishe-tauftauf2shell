#!/usr/bin/env bash
# W12: is the W10 chosen-address dereference an optimization-level artifact?
# Builds the pinned glTF-only library at -O0/-O2/-O3 with the same explicit
# flags (no CMAKE_BUILD_TYPE; NDEBUG supplied explicitly so ai_assert stays
# compiled out), then feeds the tracked crafted documents through the same
# ReadFileFromMemory driver at the matching driver optimization level.
# A different fault address or frame is a preserved negative observation,
# not a harness failure. Author-measured, unwitnessed, no r5.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
mkdir -p w12/evidence harness/bin
common='-g -U_FORTIFY_SOURCE -DNDEBUG -fno-omit-frame-pointer'
trace=w12/evidence/w12.trace
log=w12/evidence/w12.log
: >"$trace"
: >"$log"

pass=0
fail=0
check() { # name, required substring in the normalized trace
    if ! grep -qF -- "$2" "$trace"; then
        printf 'FAIL %s (missing: %s)\n' "$1" "$2" | tee -a "$log"
        fail=$((fail + 1))
    else
        printf 'PASS %s\n' "$1" | tee -a "$log"
        pass=$((pass + 1))
    fi
}
check_file() { # name, file, required substring
    if ! grep -qF -- "$3" "$2"; then
        printf 'FAIL %s (missing: %s in %s)\n' "$1" "$3" "$2" | tee -a "$log"
        fail=$((fail + 1))
    else
        printf 'PASS %s\n' "$1" | tee -a "$log"
        pass=$((pass + 1))
    fi
}


sha256sum "$src/code/AssetLib/glTF/glTFAsset.inl" \
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >w12/evidence/source-hashes.out

python3 - >w12/evidence/bytes.out <<'PY'
import base64, json, struct
for name in ("idxptr-zero", "idxptr-addr42"):
    with open("harness/cases/%s.gltf" % name) as f:
        uri = json.load(f)["buffers"]["buf"]["uri"]
    raw = base64.b64decode(uri.split(",", 1)[1])
    w0, w1 = struct.unpack("<II", raw[48:56])
    print("%s word0=%08x word1=%08x" % (name, w0, w1))
PY

for opt in 0 2 3; do
    variant="o$opt"
    bld="build-min-plain-nf-$variant"
    if [ ! -f "$bld/bin/libassimp.so.6.0.6" ]; then
        cmake -G Ninja -S "$src" -B "$bld" \
            -DCMAKE_BUILD_TYPE= \
            -DCMAKE_C_FLAGS="-O$opt $common" \
            -DCMAKE_CXX_FLAGS="-O$opt $common" \
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
    grep -m1 '^  FLAGS = ' "$bld/build.ninja" >"w12/evidence/$variant-flags.txt"
    g++ "-O$opt" $common -DPLAIN_READ \
        -I "$src/include" -I "$bld/include" \
        harness/placement_driver.cpp -L "$bld/bin" -lassimp \
        -Wl,-rpath,"$PWD/$bld/bin" -o "harness/bin/w12_$variant"

    # Run the safe document first: it must import cleanly in every variant.
    rc=0
    harness/bin/w12_$variant harness/cases/safe.gltf >"w12/evidence/$variant-safe.out" 2>&1 || rc=$?
    printf 'CASE %s safe rc=%s\n' "$variant" "$rc" >>"$trace"
    if grep -q '^case=.*scene=ok' "w12/evidence/$variant-safe.out"; then
        printf 'SCENE %s safe ok\n' "$variant" >>"$trace"
    fi

    for c in idxptr-zero idxptr-addr42; do
        rc=0
        harness/bin/w12_$variant "harness/cases/$c.gltf" >"w12/evidence/$variant-$c.out" 2>&1 || rc=$?
        printf 'CASE %s %s rc=%s\n' "$variant" "$c" "$rc" >>"$trace"
        if [ "$rc" -eq 139 ]; then
            gdb -q -batch -x harness/w12_fault.gdb \
                --args harness/bin/w12_$variant "harness/cases/$c.gltf" \
                >"w12/evidence/$variant-$c-gdb.out" 2>&1 || true
            addr=$(grep -m1 '^FAULT ' "w12/evidence/$variant-$c-gdb.out" || true)
            if [ -n "$addr" ]; then
                printf 'FAULT %s %s %s\n' "$variant" "$c" "${addr#FAULT }" >>"$trace"
            fi
            if grep -qF 'CopyVector<aiMesh>' "w12/evidence/$variant-$c-gdb.out"; then
                printf 'FRAME %s %s copyvector\n' "$variant" "$c" >>"$trace"
            elif grep -qF '__memcpy' "w12/evidence/$variant-$c-gdb.out"; then
                printf 'FRAME %s %s memcpy\n' "$variant" "$c" >>"$trace"
            else
                printf 'FRAME %s %s other\n' "$variant" "$c" >>"$trace"
            fi
        elif [ "$rc" -eq 134 ]; then
            gdb -q -batch -x harness/w12_fault.gdb \
                --args harness/bin/w12_$variant "harness/cases/$c.gltf" \
                >"w12/evidence/$variant-$c-gdb.out" 2>&1 || true
            kind=other
            if grep -qF 'stack smashing detected' "w12/evidence/$variant-$c-gdb.out"; then
                kind=canary
            fi
            printf 'ABORT %s %s rc=%s %s\n' "$variant" "$c" "$rc" "$kind" >>"$trace"
        elif grep -q '^case=.*scene=ok' "w12/evidence/$variant-$c.out"; then
            printf 'SCENE %s %s ok\n' "$variant" "$c" >>"$trace"
        fi
    done

    z=$(grep -m1 "^FAULT $variant idxptr-zero " "$trace" || true)
    a=$(grep -m1 "^FAULT $variant idxptr-addr42 " "$trace" || true)
    zf=$(grep -m1 "^FRAME $variant idxptr-zero " "$trace" || true)
    af=$(grep -m1 "^FRAME $variant idxptr-addr42 " "$trace" || true)
    if [[ "$z" == *'si_addr=0x41414141'* && "$a" == *'si_addr=0x42424242'* ]] \
       && [[ "$zf" == *copyvector && "$af" == *copyvector ]]; then
        verdict=PORTABLE
    else
        verdict=DIFFERENT
    fi
    printf 'VERDICT %s %s\n' "$variant" "$verdict" | tee -a "$log" >>"$trace"
done

check safe-o0 'SCENE o0 safe ok'
check safe-o2 'SCENE o2 safe ok'
check safe-o3 'SCENE o3 safe ok'
check_file chosen-zero-bytes w12/evidence/bytes.out 'idxptr-zero word0=41414141 word1=00000000'
check_file chosen-addr42-bytes w12/evidence/bytes.out 'idxptr-addr42 word0=42424242 word1=00000000'
check_file o0-flags w12/evidence/o0-flags.txt '-O0 '
check_file o2-flags w12/evidence/o2-flags.txt '-O2 '
check_file o3-flags w12/evidence/o3-flags.txt '-O3 '
for opt in 0 2 3; do
    for c in idxptr-zero idxptr-addr42; do
        if grep -qE "^(FAULT|SCENE|ABORT) o$opt $c " "$trace"; then
            printf 'PASS observed-o%s-%s\n' "$opt" "$c" | tee -a "$log"
            pass=$((pass + 1))
        else
            printf 'FAIL observed-o%s-%s\n' "$opt" "$c" | tee -a "$log"
            fail=$((fail + 1))
        fi
    done
done
check verdict-o0 'VERDICT o0 '
check verdict-o2 'VERDICT o2 '
check verdict-o3 'VERDICT o3 '

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log" >>"$trace"
sha256sum w12/evidence/*.out "$trace" | tee -a "$log"
[ "$fail" -eq 0 ]
