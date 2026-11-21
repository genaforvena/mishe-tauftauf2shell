#!/usr/bin/env bash
# Source-bound libwebsockets HPACK chosen-byte OOB write harness.
# All inputs are local argv values standing in for an HPACK-decoded :path byte;
# no HTTP/2 server, socket or external system is contacted.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ulimit -c 0 2>/dev/null || true
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
for t in vuln fixed vuln_asan fixed_asan; do
  gcc -std=c11 -O0 -g -o "$OUT/$t" "driver_$([ "$t" = vuln ] || [ "$t" = fixed ] && echo "$t" || echo "${t%_asan}").c" \
    $(case "$t" in *_asan) echo '-fsanitize=address -fno-omit-frame-pointer';; esac) || exit 2
done
V="$OUT/vuln"; F="$OUT/fixed"; VA="$OUT/vuln_asan"; FA="$OUT/fixed_asan"

r1=$($V collab 16 0x5a); echo "$r1"
check "rung1 write past 16-byte limit" "$(yes 'rv=1 pos=17 oob0=5a' "$r1")"

r2=$($V chain 16 0x5a); echo "$r2"
ok=0
contains 'r1=1 r2=1 pos=17 last=41' "$r2" &&
contains 'oob0=5a oob1=00' "$r2" && ok=1
check "rung2 chosen byte readback, neighbour intact" "$ok"

rv=$($V chain 16 0xa5); echo "$rv"
check "chosen value 0xa5, not a fixed marker" "$(yes 'oob0=a5' "$rv")"

"$VA" exact 16 0x5a > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 1' "$ac" &&
contains 'hpack_v4.3.10:277' "$ac" && ok=1
check "rung3 ASan write at pinned :277" "$ok"

ok=1
for n in 16 32 48; do
  ro=$($V chain "$n" 0x5a); echo "$ro"
  contains "limit=$n c=5a" "$ro" && contains 'oob0=5a' "$ro" || ok=0
done
check "rung4 chosen 0x5a at offsets 16/32/48" "$ok"

( "$V" guard 16 0x5a > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page fault on first past-end write" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

fc=$($F collab 16 0x5a); echo "$fc"
check "fixed rejects hostile before write" "$(yes 'rv=1 pos=16 oob0=00' "$fc")"

fi=$($F inbounds 16 0x41); echo "$fi"
check "fixed accepts in-bounds byte" "$(yes 'rv=1 pos=16 last=41' "$fi")"

"$VA" exactok 16 0x41 > "$OUT/vuln_benign_asan.log" 2>&1; a=$?
"$FA" exact 16 0x5a > "$OUT/fixed_bad_asan.log" 2>&1; b=$?
"$FA" exactok 16 0x41 > "$OUT/fixed_good_asan.log" 2>&1; c=$?
ok=0
[ "$a" -eq 0 ] && [ "$b" -eq 0 ] && [ "$c" -eq 0 ] &&
! contains 'AddressSanitizer' "$(cat "$OUT/vuln_benign_asan.log")" &&
! contains 'AddressSanitizer' "$(cat "$OUT/fixed_bad_asan.log")" &&
! contains 'AddressSanitizer' "$(cat "$OUT/fixed_good_asan.log")" && ok=1
check "ASan clean: vulnerable benign, fixed hostile+benign" "$ok"

group() {
  for i in 1 2 3 4 5; do
    "$V" collab 16 0x5a; "$V" chain 16 0x5a; "$V" chain 32 0x5a
    "$V" chain 48 0x5a; "$F" chain 16 0x5a; "$V" inbounds 16 0x41
  done | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
