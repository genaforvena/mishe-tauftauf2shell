#!/usr/bin/env bash
# One-command local verification for CVE-2026-95520 (rpm iterReadArchiveNext).
set -u
cd "$(dirname "$0")"
mkdir -p out

pass=0
fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; fail=$((fail+1)); }
has()  { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

# -O0 is deliberate: GCC 13 at -O1 inlines rpmcpioRead and its ASan build
# misses the overflow; this negative is recorded in PROVENANCE.md.
ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O0 -g"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

echo "== build =="
gcc   $ASAN_FLAGS -o out/asan-vuln harness/driver.c && ok "gcc asan vulnerable build" || bad "gcc asan vulnerable build"
clang $ASAN_FLAGS -o out/clang-asan-vuln harness/driver.c && ok "clang asan vulnerable build" || bad "clang asan vulnerable build"
gcc   $ASAN_FLAGS -DVARIANT_FIXED -o out/asan-fixed harness/driver.c && ok "gcc asan fixed build" || bad "gcc asan fixed build"
gcc   -O0 -g -DPLAIN_MODE -o out/plain-vuln harness/driver.c && ok "plain vulnerable build" || bad "plain vulnerable build"
gcc   -O0 -g -DPLAIN_MODE -DVARIANT_FIXED -o out/plain-fixed harness/driver.c && ok "plain fixed build" || bad "plain fixed build"

echo "== runs =="
out/asan-vuln       attack > out/gcc-attack.log 2>&1 || true
out/clang-asan-vuln attack > out/clang-attack.log 2>&1 || true
out/asan-fixed      attack > out/fixed-attack.log 2>&1 || true
out/asan-vuln       safe   > out/vuln-safe.log 2>&1 || true
out/asan-fixed      safe   > out/fixed-safe.log 2>&1 || true
out/plain-vuln      attack > out/plain-attack.log 2>&1 || true
out/plain-vuln      safe   > out/plain-safe.log 2>&1 || true
out/plain-fixed     attack > out/plain-fixed-attack.log 2>&1 || true

echo "== gcc ASan attack (header symlink size UINT64_MAX) =="
has out/gcc-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "gcc ASan heap-buffer-overflow" || bad "gcc ASan heap-buffer-overflow"
has out/gcc-attack.log "WRITE of size 64" && ok "gcc ASan WRITE of size 64" || bad "gcc ASan WRITE of size 64"
has out/gcc-attack.log "0 bytes after 1-byte region" && ok "gcc ASan 0 bytes after 1-byte region" || bad "gcc ASan 0 bytes after 1-byte region"
has out/gcc-attack.log "iterReadArchiveNext" && ok "ASan stack names pinned iterReadArchiveNext" || bad "ASan stack names pinned iterReadArchiveNext"

echo "== clang ASan attack =="
has out/clang-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "clang ASan heap-buffer-overflow" || bad "clang ASan heap-buffer-overflow"
has out/clang-attack.log "WRITE of size 64" && ok "clang ASan WRITE of size 64" || bad "clang ASan WRITE of size 64"
has out/clang-attack.log "0 bytes after 1-byte region" && ok "clang ASan 0 bytes after 1-byte region" || bad "clang ASan 0 bytes after 1-byte region"

echo "== fix control =="
hasnt out/fixed-attack.log "AddressSanitizer" && ok "fixed build ASan-clean on attack" || bad "fixed build ASan-clean on attack"
has out/fixed-attack.log "RET=-15" && ok "fixed build rejects header/payload size mismatch" || bad "fixed build rejects header/payload size mismatch"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed build ASan-clean on safe input" || bad "fixed build ASan-clean on safe input"
has out/fixed-safe.log "RET=0" && ok "fixed build accepts matching symlink size" || bad "fixed build accepts matching symlink size"

echo "== safe-input control on vulnerable body =="
hasnt out/vuln-safe.log "AddressSanitizer" && ok "vulnerable build ASan-clean on safe input" || bad "vulnerable build ASan-clean on safe input"
has out/vuln-safe.log "RET=0" && ok "vulnerable build accepts safe input" || bad "vulnerable build accepts safe input"

echo "== plain chosen-byte readback =="
has out/plain-attack.log "RET=-13" && ok "vulnerable plain body reports read failure" || bad "vulnerable plain body reports read failure"
has out/plain-attack.log "CANARY_AFTER=495348452d52504d2121414141414141" && ok "chosen MISHE-RPM!! past 1-byte allocation" || bad "chosen MISHE-RPM!! past 1-byte allocation"
has out/plain-safe.log "RET=0" && ok "plain safe input succeeds" || bad "plain safe input succeeds"
hasnt out/plain-safe.log "CANARY_AFTER=" && ok "plain safe input writes no canary" || bad "plain safe input writes no canary"
has out/plain-fixed-attack.log "RET=-15" && ok "plain fixed build rejects attack" || bad "plain fixed build rejects attack"
hasnt out/plain-fixed-attack.log "CANARY_AFTER=" && ok "plain fixed build writes no canary" || bad "plain fixed build writes no canary"

echo "== pins =="
for pair in "pins/iter-vulnerable.inc dd72be1bdb92c68b2d97e38f977344cc5b411c56ee16952e2d1010d8ed49e9ff" \
            "pins/iter-fixed.inc 0c00ded194575ec9649e3532ff09713faa5e96b36acb10524fb5adc776b92721" \
            "pins/rpmfi-vulnerable.cc 51d5d7c96773ca2e00c20e5cba7f049d896300d9f255d0fffadd4193fa7ccf27" \
            "pins/rpmfi-fixed.cc eaca65fdb04b9b8fe7647f2df4aa033d7b40d850500e7c82f9a91a3d87cb376a"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin hash $1" || bad "pin hash $1"
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
