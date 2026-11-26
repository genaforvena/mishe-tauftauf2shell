#!/usr/bin/env bash
# One-command local verification for CVE-2026-77396 (pjproject AVI player).
set -u
cd "$(dirname "$0")"
mkdir -p out

pass=0
fail=0
ok()   { echo "PASS $1"; pass=$((pass+1)); }
bad()  { echo "FAIL $1"; fail=$((fail+1)); }
has()  { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

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

echo "== gcc ASan attack (64-byte AVI video chunk into 48-byte frame) =="
has out/gcc-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "gcc ASan heap-buffer-overflow" || bad "gcc ASan heap-buffer-overflow"
has out/gcc-attack.log "WRITE of size 64" && ok "gcc ASan WRITE of size 64" || bad "gcc ASan WRITE of size 64"
has out/gcc-attack.log "0 bytes after 48-byte region" && ok "gcc ASan 0 bytes after 48-byte region" || bad "gcc ASan 0 bytes after 48-byte region"
has out/gcc-attack.log "avi_get_frame" && ok "ASan stack names pinned avi_get_frame" || bad "ASan stack names pinned avi_get_frame"
has out/gcc-attack.log "avi-vulnerable.inc:15" && ok "ASan write frame pins vulnerable excerpt" || bad "ASan write frame pins vulnerable excerpt"

echo "== clang ASan attack =="
has out/clang-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "clang ASan heap-buffer-overflow" || bad "clang ASan heap-buffer-overflow"
has out/clang-attack.log "WRITE of size 64" && ok "clang ASan WRITE of size 64" || bad "clang ASan WRITE of size 64"
has out/clang-attack.log "0 bytes after 48-byte region" && ok "clang ASan 0 bytes after 48-byte region" || bad "clang ASan 0 bytes after 48-byte region"

echo "== fix control =="
hasnt out/fixed-attack.log "AddressSanitizer" && ok "fixed build ASan-clean on attack" || bad "fixed build ASan-clean on attack"
has out/fixed-attack.log "AVI_FRAME_SIZE=48" && ok "fixed build clamps read to frame capacity" || bad "fixed build clamps read to frame capacity"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed build ASan-clean on safe input" || bad "fixed build ASan-clean on safe input"
has out/fixed-safe.log "AVI_FRAME_SIZE=48" && ok "fixed build accepts matching chunk length" || bad "fixed build accepts matching chunk length"

echo "== safe-input control on vulnerable body =="
hasnt out/vuln-safe.log "AddressSanitizer" && ok "vulnerable build ASan-clean on safe input" || bad "vulnerable build ASan-clean on safe input"
has out/vuln-safe.log "AVI_FRAME_SIZE=48" && ok "vulnerable build accepts safe input" || bad "vulnerable build accepts safe input"

echo "== plain chosen-byte readback =="
has out/plain-attack.log "AVI_FRAME_SIZE=64" && ok "vulnerable plain body adopts file-supplied length" || bad "vulnerable plain body adopts file-supplied length"
has out/plain-attack.log "CANARY_AFTER=4d495348452d504a50524f4a45435421" && ok "chosen MISHE-PJPROJECT! past 48-byte frame" || bad "chosen MISHE-PJPROJECT! past 48-byte frame"
has out/plain-safe.log "AVI_FRAME_SIZE=48" && ok "plain safe input stays in frame" || bad "plain safe input stays in frame"
hasnt out/plain-safe.log "4d495348452d504a" && ok "plain safe input writes no chosen marker" || bad "plain safe input writes no chosen marker"
has out/plain-fixed-attack.log "AVI_FRAME_SIZE=48" && ok "plain fixed build clamps attack" || bad "plain fixed build clamps attack"
hasnt out/plain-fixed-attack.log "4d495348452d504a" && ok "plain fixed build writes no chosen marker" || bad "plain fixed build writes no chosen marker"

echo "== pins =="
for pair in "pins/avi-vulnerable.inc 45fe04f09520dfef6f2cc52f70d6293a4fdd96e7f76d6eb41a79e2586e710ba1" \
            "pins/avi-fixed.inc 2cc1805d5dee8959837926dcb492ffb3b53de4b2a2b4e063f0afc4f3f11139de" \
            "src/avi_player-vuln.c 1ccafcd255ad996e572753495191ff5347b2062c9152617458425f30c9446081" \
            "src/avi_player-fixed.c dae6aeee810d88173657cefb3486f89bdee77dbe87b2520a5ae784f854fc5042"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin hash $1" || bad "pin hash $1"
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
