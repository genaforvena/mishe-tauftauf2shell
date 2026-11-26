#!/usr/bin/env bash
# One-command local verification for CVE-2026-81878 (radare2 PYC get_bytes wrap).
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
out/asan-vuln       attack > out/gcc-attack.log 2>&1 || true
out/clang-asan-vuln attack > out/clang-attack.log 2>&1 || true
out/asan-fixed      attack > out/fixed-attack.log 2>&1 || true
out/asan-fixed      safe   > out/fixed-safe.log 2>&1 || true
out/asan-vuln       safe   > out/vuln-safe.log 2>&1 || true
out/plain-vuln      attack > out/plain-attack.log 2>&1 || true
out/plain-vuln      safe   > out/plain-safe.log 2>&1 || true
out/plain-fixed     attack > out/plain-fixed-attack.log 2>&1 || true

echo "== gcc ASan attack (0xffffffff -> calloc(0,1) -> memset 4294967295) =="
has out/gcc-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "gcc ASan heap-buffer-overflow" || bad "gcc ASan heap-buffer-overflow"
has out/gcc-attack.log "WRITE of size 4294967295" && ok "gcc ASan WRITE of pinned sink length" || bad "gcc ASan WRITE of pinned sink length"
has out/gcc-attack.log "r_buf_read .*pins/buf-sink.inc:496" && ok "ASan fault frame pins r_buf_read memset" || bad "ASan fault frame pins r_buf_read memset"
has out/gcc-attack.log "get_bytes .*pins/get-bytes-vulnerable.inc:2" && ok "ASan allocation frame pins vulnerable get_bytes" || bad "ASan allocation frame pins vulnerable get_bytes"

echo "== clang ASan attack =="
has out/clang-attack.log "AddressSanitizer: heap-buffer-overflow" && ok "clang ASan heap-buffer-overflow" || bad "clang ASan heap-buffer-overflow"
has out/clang-attack.log "WRITE of size 4294967295" && ok "clang ASan WRITE length" || bad "clang ASan WRITE length"
has out/clang-attack.log "r_buf_read .*pins/buf-sink.inc:496" && ok "clang ASan frame pins sink" || bad "clang ASan frame pins sink"

echo "== fixed and safe-input controls =="
hasnt out/fixed-attack.log "AddressSanitizer" && ok "fixed build ASan-clean on attack" || bad "fixed build ASan-clean on attack"
has out/fixed-attack.log "MODE=attack LEN_FIELD=4294967295 RC=3 SINK=0" && ok "fixed build rejects unvalidated size before allocation" || bad "fixed build rejects unvalidated size before allocation"
hasnt out/fixed-safe.log "AddressSanitizer" && ok "fixed build ASan-clean on safe input" || bad "fixed build ASan-clean on safe input"
has out/fixed-safe.log "MODE=safe LEN_FIELD=16 RC=0 SINK=0" && ok "fixed build accepts safe marshal length" || bad "fixed build accepts safe marshal length"
hasnt out/vuln-safe.log "AddressSanitizer" && ok "vulnerable build ASan-clean on safe input" || bad "vulnerable build ASan-clean on safe input"
has out/vuln-safe.log "MODE=safe LEN_FIELD=16 RC=0 SINK=0" && ok "vulnerable build accepts safe marshal length" || bad "vulnerable build accepts safe marshal length"

echo "== plain bounded sink readback =="
has out/plain-attack.log "SINK_R=0 SINK_LEN=4294967295 SINK_BYTE=ff" && ok "sink is reached with ~4GB memset length from crafted field" || bad "sink is reached with ~4GB memset length from crafted field"
has out/plain-attack.log "MODE=attack LEN_FIELD=4294967295 RC=3 SINK=1" && ok "post-check rejects only after the sink already wrote" || bad "post-check rejects only after the sink already wrote"
hasnt out/plain-safe.log "SINK_BUF=" && ok "safe input never calls the sink" || bad "safe input never calls the sink"
has out/plain-fixed-attack.log "MODE=attack LEN_FIELD=4294967295 RC=3 SINK=0" && ok "plain fixed build rejects attack without sink" || bad "plain fixed build rejects attack without sink"

echo "== pins =="
for pair in "src/marshal-6.1.8.c 41698e7886715b57427b166c90101aa132eadec821de66fccbf477a147cbb51c" \
            "src/marshal-fix-6727454.c 3d8b2a625a96a750ad2135a32d975715f91a262d6bd71695b5ed9982bcf0c313" \
            "src/marshal-6.2.0.c 0aedf7fb536fbfeb6c5cdb7804dce6a40e15807cfe107a0ac6c31c7115f4a45c" \
            "src/buf-6.1.8.c 538a6784eeb0e7f673625f73fce58e97c957f2b3dd41b90528d2f4b57493a52f" \
            "pins/get-bytes-vulnerable.inc a3f2083495e1e6205fc77934167ae195a3968607bdc5b24f0aa653f6962c396f" \
            "pins/get-bytes-fixed.inc 8e41575a6e315364b95e125524db2fa9e28d8347b27dae8bf5c4004c95cff9ba" \
            "pins/ascii-readers.inc d19406980365f39859bcee067be6a940fcad812ddf23d0db48476484b16ed26e" \
            "pins/buf-sink.inc 4f3e1082ed37fd99f92d010c3b7037ef955583c9b795603d4c1de89892d5c9dd" \
            "harness/driver.c 6995deba366eba8e92523316bf3230470397cce4291538b4912d5290ad485ce3"; do
    set -- $pair
    got=$(sha256sum "$1" | cut -d' ' -f1)
    [ "$got" = "$2" ] && ok "pin hash $1" || bad "pin hash $1"
done

echo "TOTAL: $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
