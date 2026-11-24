#!/usr/bin/env bash
# W11: does the W10 chosen-address dereference survive a second compiler?
# Uses the same source, crafted documents and driver as run-w10.sh, with a
# clang -O1 -g -U_FORTIFY_SOURCE library and driver instead of gcc.
# This is a measurement harness: an unexpected fault address is a preserved
# negative observation, not a harness failure. Author-only, no r5.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
bld=build-min-plain-nf-clang
if [ ! -f "$bld/bin/libassimp.so.6.0.6" ]; then
    cmake -G Ninja -S "$src" -B "$bld" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
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
mkdir -p w11/evidence harness/bin
clang++ -O1 -g -DPLAIN_READ \
    -I "$src/include" -I "$bld/include" \
    harness/placement_driver.cpp -L "$bld/bin" -lassimp \
    -Wl,-rpath,"$PWD/$bld/bin" -o harness/bin/w11_plain_clang

log=w11/evidence/w11.log
trace=w11/evidence/w11.trace
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
    harness/bin/w11_plain_clang "harness/cases/$c.gltf" >"$out" 2>&1 || rc=$?
    printf '# case=%s rc=%s\n' "$c" "$rc" >>"$out"
    printf 'case=%s rc=%s\n' "$c" "$rc" >>"$trace"
    grep -E '^case=.*scene=' "$out" >>"$trace" || true
}
run_gdb() { # case, output
    local c="$1" out="$2"
    gdb -q -batch -x harness/w11_fault.gdb \
        --args harness/bin/w11_plain_clang "harness/cases/$c.gltf" >"$out" 2>&1 || true
    grep -E '^(FAULT|FRAME3)' "$out" >>"$trace" || true
}

python3 - >w11/evidence/bytes.out <<'PY'
import base64, json, struct
for name in ("idxptr-zero", "idxptr-addr42"):
    with open("harness/cases/%s.gltf" % name) as f:
        uri = json.load(f)["buffers"]["buf"]["uri"]
    raw = base64.b64decode(uri.split(",", 1)[1])
    w0, w1 = struct.unpack("<II", raw[48:56])
    print("%s word0=%08x word1=%08x" % (name, w0, w1))
with open("harness/cases/idxptr-stride42.gltf") as f:
    uri = json.load(f)["buffers"]["buf"]["uri"]
raw = base64.b64decode(uri.split(",", 1)[1])
print("idxptr-stride42 offset76=%02x" % raw[76])
PY

run_direct safe w11/evidence/safe.out
check safe-scene-ok w11/evidence/safe.out 'scene=ok' 'Segmentation fault'
for c in idxptr-zero idxptr-addr42 idxptr-42 idxptr-43 idxptr-stride42; do
    run_direct "$c" "w11/evidence/$c.out"
done
check zero-crash w11/evidence/idxptr-zero.out '# case=idxptr-zero rc=139'
check addr42-crash w11/evidence/idxptr-addr42.out '# case=idxptr-addr42 rc=139'
check ptr42-crash w11/evidence/idxptr-42.out '# case=idxptr-42 rc=139'
check ptr43-crash w11/evidence/idxptr-43.out '# case=idxptr-43 rc=139'
check stride42-crash w11/evidence/idxptr-stride42.out '# case=idxptr-stride42 rc=139'
check chosen-zero-bytes w11/evidence/bytes.out 'idxptr-zero word0=41414141 word1=00000000'
check chosen-addr42-bytes w11/evidence/bytes.out 'idxptr-addr42 word0=42424242 word1=00000000'
check chosen-stride42-byte w11/evidence/bytes.out 'idxptr-stride42 offset76=42'

run_gdb idxptr-zero w11/evidence/gdb-zero.out
run_gdb idxptr-addr42 w11/evidence/gdb-addr42.out
run_gdb idxptr-stride42 w11/evidence/gdb-stride42.out
zero_fault=$(grep -m1 '^FAULT ' w11/evidence/gdb-zero.out || true)
addr42_fault=$(grep -m1 '^FAULT ' w11/evidence/gdb-addr42.out || true)
stride_fault=$(grep -m1 '^FAULT ' w11/evidence/gdb-stride42.out || true)
printf 'OBSERVE zero %s\nOBSERVE addr42 %s\nOBSERVE stride42 %s\n' "$zero_fault" "$addr42_fault" "$stride_fault" | tee -a "$log" >>"$trace"
zero_rsi=$(printf '%s\n' "$zero_fault" | grep -o -E 'rsi=0x[0-9a-f]+' | cut -d= -f2 || true)
stride_rsi=$(printf '%s\n' "$stride_fault" | grep -o -E 'rsi=0x[0-9a-f]+' | cut -d= -f2 || true)
if [ -n "$zero_rsi" ] && [ -n "$stride_rsi" ] && [ "$zero_rsi" != "$stride_rsi" ]; then
    printf 'PASS stride-byte-steers-source rsi %s -> %s delta=%d\n' \
        "$zero_rsi" "$stride_rsi" "$((16#${stride_rsi#0x} - 16#${zero_rsi#0x}))" | tee -a "$log" >>"$trace"
    pass=$((pass+1))
else
    printf 'FAIL stride-byte-steers-source\n' | tee -a "$log" >>"$trace"; fail=$((fail+1))
fi
if [[ "$zero_fault" == *'si_addr=0x41414141'* && "$addr42_fault" == *'si_addr=0x42424242'* ]]; then
    verdict='PORTABLE'
else
    verdict='DIFFERENT'
fi
printf 'VERDICT %s\n' "$verdict" | tee -a "$log" >>"$trace"
printf 'RESULT %s PASS / %s FAIL\n' "$pass" "$fail" | tee -a "$log" >>"$trace"
sha256sum w11/evidence/*.out w11/evidence/w11.trace | tee -a "$log"
[ "$fail" -eq 0 ]
