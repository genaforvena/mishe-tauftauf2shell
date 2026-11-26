#!/usr/bin/env bash
# One-command local verification for CVE-2026-86138 (libxml2 xmlDictAddQString).
set -u
cd "$(dirname "$0")"
mkdir -p out

pass=0
fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; fail=$((fail+1)); }
has()  { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O1 -g"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

echo "== build =="
gcc   $ASAN_FLAGS -o out/asan-vuln       harness/driver.c && ok "gcc asan vulnerable build" || bad "gcc asan vulnerable build"
clang $ASAN_FLAGS -o out/clang-asan-vuln harness/driver.c && ok "clang asan vulnerable build" || bad "clang asan vulnerable build"
gcc   $ASAN_FLAGS -DVARIANT_FIXED -o out/asan-fixed harness/driver.c && ok "gcc asan fixed build" || bad "gcc asan fixed build"
gcc   -O0 -g -DPLAIN_MODE -o out/plain-vuln harness/driver.c && ok "plain vulnerable build" || bad "plain vulnerable build"

echo "== runs =="
out/asan-vuln       attack  > out/gcc-attack.log 2>&1 || true
out/clang-asan-vuln attack  > out/clang-attack.log 2>&1 || true
out/asan-fixed      attack  > out/fixed-attack.log 2>&1 || true
out/asan-vuln       wrap1k  > out/vuln-wrap1k.log 2>&1 || true
out/asan-fixed      wrap1k  > out/fixed-wrap1k.log 2>&1 || true
out/asan-vuln       safe    > out/vuln-safe.log 2>&1 || true
out/asan-fixed      safe    > out/fixed-safe.log 2>&1 || true
out/plain-vuln      attack  > out/plain-attack.log 2>&1 || true
out/plain-vuln      safe    > out/plain-safe.log 2>&1 || true

echo "== gcc ASan attack (sum wraps to 0) =="
has out/gcc-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "gcc ASan heap-buffer-overflow" || bad "gcc ASan heap-buffer-overflow"
has out/gcc-attack.log "WRITE of size 4294967280" && ok "gcc ASan WRITE of size 4294967280" || bad "gcc ASan WRITE of size 4294967280"
has out/gcc-attack.log "0 bytes after 1048-byte region" && ok "gcc ASan 0 bytes after 1048-byte region" || bad "gcc ASan 0 bytes after 1048-byte region"
has out/gcc-attack.log "xmlDictAddQString" && ok "ASan stack names pinned xmlDictAddQString" || bad "ASan stack names pinned xmlDictAddQString"

echo "== clang ASan attack =="
has out/clang-attack.log "AddressSanitizer" && ok "clang ASan fires" || bad "clang ASan fires"
has out/clang-attack.log "WRITE of size 4294967280" && ok "clang ASan WRITE of size 4294967280" || bad "clang ASan WRITE of size 4294967280"

echo "== fixed control: incomplete fix on wrap-to-zero (negative result) =="
has out/fixed-attack.log "AddressSanitizer" && ok "v2.15.4 fix still overflows on wrap-0" || bad "v2.15.4 fix still overflows on wrap-0"
has out/fixed-attack.log "WRITE of size 4294967280" && ok "v2.15.4 fix WRITE size unchanged" || bad "v2.15.4 fix WRITE size unchanged"

echo "== fixed control: wrap-to-1000 (fix rejects) =="
has out/vuln-wrap1k.log "AddressSanitizer" && ok "vulnerable ASan fires on wrap-1000" || bad "vulnerable ASan fires on wrap-1000"
hasnt out/fixed-wrap1k.log "AddressSanitizer" && ok "fixed build ASan-clean on wrap-1000" || bad "fixed build ASan-clean on wrap-1000"
has out/fixed-wrap1k.log "RET=NULL" && ok "fixed build rejects wrap-1000 QName" || bad "fixed build rejects wrap-1000 QName"

echo "== safe-input controls =="
hasnt out/vuln-safe.log "AddressSanitizer" && ok "vulnerable build ASan-clean on safe input" || bad "vulnerable build ASan-clean on safe input"
has out/vuln-safe.log "RET=non-NULL" && ok "vulnerable build accepts safe QName" || bad "vulnerable build accepts safe QName"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed build ASan-clean on safe input" || bad "fixed build ASan-clean on safe input"
has out/fixed-safe.log "RET=non-NULL" && ok "fixed build accepts safe QName" || bad "fixed build accepts safe QName"

echo "== plain chosen-byte readback =="
has out/plain-attack.log "SIGSEGV_CAUGHT=1" && ok "plain attack faults at heap boundary" || bad "plain attack faults at heap boundary"
has out/plain-attack.log "CANARY_AFTER=4d495348452d4c4942584d4c32212100" && ok "chosen MISHE-LIBXML2!! past pool" || bad "chosen MISHE-LIBXML2!! past pool"
hasnt out/plain-safe.log "SIGSEGV_CAUGHT=1" && ok "plain safe input does not fault" || bad "plain safe input does not fault"

echo "== pins =="
for pair in "pins/dict-vulnerable.inc c2a4a0ed9ffe8fabffc9f0e19de8c3d1ca59fee80dc68f454211ad511a7f0d9a" \
            "pins/dict-fixed.inc 035611cca31f6bdb67b030c221c8fb7445750d841479e6f4f2a7e8874c28b9d4" \
            "pins/dict-v2.15.3.c 416253664eb3d95a393be6c61c649a1b5600729bbd1e3ce9123df08b12d8f388" \
            "pins/dict-v2.15.4.c 2663392f29dd45eb7ad802c471e146d4f6f509e317a4938b496920b4ea0228b4"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin hash $1" || bad "pin hash $1"
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
