#!/usr/bin/env bash
# One-command local verification for CVE-2025-71473 (lwext4 inode bitmap).
set -u
cd "$(dirname "$0")"
mkdir -p out

pass=0
fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; fail=$((fail+1)); }
has()  { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O0 -g -I."
PLAIN_FLAGS="-O0 -g -I. -DPLAIN_MODE"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

echo "== build =="
gcc   $ASAN_FLAGS -o out/asan-vuln harness/driver.c && ok "gcc ASan vulnerable build" || bad "gcc ASan vulnerable build"
clang $ASAN_FLAGS -o out/clang-asan-vuln harness/driver.c && ok "clang ASan vulnerable build" || bad "clang ASan vulnerable build"
gcc   $ASAN_FLAGS -DVARIANT_FIXED -o out/asan-fixed harness/driver.c && ok "gcc ASan fixed build" || bad "gcc ASan fixed build"
gcc   $PLAIN_FLAGS -o out/plain-vuln harness/driver.c && ok "plain vulnerable build" || bad "plain vulnerable build"
gcc   $PLAIN_FLAGS -DVARIANT_FIXED -o out/plain-fixed harness/driver.c && ok "plain fixed build" || bad "plain fixed build"

echo "== runs =="
out/asan-vuln       attack  > out/gcc-attack.log 2>&1 || true
out/clang-asan-vuln attack  > out/clang-attack.log 2>&1 || true
out/asan-vuln       attack2 > out/gcc-attack2.log 2>&1 || true
out/asan-fixed      attack  > out/fixed-attack.log 2>&1 || true
out/asan-fixed      safe    > out/fixed-safe.log 2>&1 || true
out/asan-vuln       safe    > out/vuln-safe.log 2>&1 || true
out/plain-vuln      attack  > out/plain-attack.log 2>&1 || true
out/plain-vuln      attack2 > out/plain-attack2.log 2>&1 || true
out/plain-vuln      safe    > out/plain-safe.log 2>&1 || true
out/plain-fixed     attack  > out/plain-fixed-attack.log 2>&1 || true
out/plain-fixed     safe    > out/plain-fixed-safe.log 2>&1 || true

echo "== gcc ASan attack (image ipg=32777 -> 4098-byte fill into 4096-byte block) =="
has out/gcc-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "gcc ASan heap-buffer-overflow" || bad "gcc ASan heap-buffer-overflow"
has out/gcc-attack.log "WRITE of size 4098" && ok "gcc ASan WRITE of pinned memset length" || bad "gcc ASan WRITE of pinned memset length"
has out/gcc-attack.log "0 bytes after 4096-byte region" && ok "write exactly past the 4096-byte block" || bad "write exactly past the 4096-byte block"
has out/gcc-attack.log "ext4_fs_init_inode_bitmap .*pins/lwext4-vulnerable.inc:23" && ok "ASan fault frame pins vulnerable memset line" || bad "ASan fault frame pins vulnerable memset line"
has out/gcc-attack.log "ext4_trans_block_get_noread .*harness/driver.c" && ok "ASan allocation frame pinned" || bad "ASan allocation frame pinned"

echo "== clang ASan attack =="
has out/clang-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "clang ASan heap-buffer-overflow" || bad "clang ASan heap-buffer-overflow"
has out/clang-attack.log "WRITE of size 4098" && ok "clang ASan WRITE length" || bad "clang ASan WRITE length"
has out/clang-attack.log "ext4_fs_init_inode_bitmap .*pins/lwext4-vulnerable.inc:23" && ok "clang ASan frame pins vulnerable excerpt" || bad "clang ASan frame pins vulnerable excerpt"
has out/gcc-attack2.log "0 bytes after 4096-byte region" && ok "second image value also overflows" || bad "second image value also overflows"

echo "== fixed and safe-input controls =="
hasnt out/fixed-attack.log "AddressSanitizer" && ok "fixed build ASan-clean on attack" || bad "fixed build ASan-clean on attack"
has out/fixed-attack.log "MODE=attack IPG=32777 RC=5 DIRTY=0" && ok "fixed build rejects unvalidated geometry with EIO" || bad "fixed build rejects unvalidated geometry with EIO"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed build ASan-clean on safe input" || bad "fixed build ASan-clean on safe input"
has out/fixed-safe.log "MODE=safe IPG=8192 RC=0 DIRTY=1" && ok "fixed build accepts safe geometry" || bad "fixed build accepts safe geometry"
hasnt out/vuln-safe.log "AddressSanitizer" && ok "vulnerable build ASan-clean on safe input" || bad "vulnerable build ASan-clean on safe input"
has out/vuln-safe.log "MODE=safe IPG=8192 RC=0 DIRTY=1" && ok "vulnerable build accepts safe geometry" || bad "vulnerable build accepts safe geometry"

echo "== plain chosen-bit readback past the logical block =="
has out/plain-attack.log "CANARY_AT=4096 FIRST=00fe4d4d4d4d4d4d" && ok "image ipg=32777 writes chosen 0xfe at block+4097" || bad "image ipg=32777 writes chosen 0xfe at block+4097"
has out/plain-attack2.log "CANARY_AT=4096 FIRST=00fc4d4d4d4d4d4d" && ok "image ipg=32778 writes chosen 0xfc at block+4097" || bad "image ipg=32778 writes chosen 0xfc at block+4097"
has out/plain-safe.log "CANARY_AT=4096 FIRST=4d4d4d4d4d4d4d4d" && ok "safe geometry writes no chosen marker" || bad "safe geometry writes no chosen marker"
has out/plain-fixed-attack.log "MODE=attack IPG=32777 RC=5 DIRTY=0" && ok "plain fixed build rejects attack geometry" || bad "plain fixed build rejects attack geometry"
has out/plain-fixed-attack.log "CANARY_AT=4096 FIRST=4d4d4d4d4d4d4d4d" && ok "plain fixed build writes no chosen marker" || bad "plain fixed build writes no chosen marker"
has out/plain-fixed-safe.log "MODE=safe IPG=8192 RC=0 DIRTY=1" && ok "plain fixed build accepts safe geometry" || bad "plain fixed build accepts safe geometry"

echo "== pins =="
for pair in "src/ext4_fs-vulnerable.c c14c4c3378abb985c28025f35d142c753e05bb6df5d171282ed83d7ccf6c09eb" \
            "src/ext4_fs-fixed.c b259a4bbe8a836d0ce7b78e6dbf0fb9eb29dbe056ce93b69cab7a2975de7bd1f" \
            "pins/lwext4-vulnerable.inc c93eaa348724a76546e9d9af248d816569f948bf7823590fdab95f38e8df9e07" \
            "pins/lwext4-fixed.inc 516bdf3b178b121881fec04d9c4f9f63a8a6a1ed53fe83155357fa9ea8d644a5" \
            "harness/driver.c 02d76df4f1ef5fdd231725e8d373f9f20a8bbf88feef144ebcac80c1a7549b42"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin hash $1" || bad "pin hash $1"
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
