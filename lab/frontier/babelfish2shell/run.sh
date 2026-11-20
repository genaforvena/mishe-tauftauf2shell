#!/usr/bin/env bash
# Driver for the Babelfish TDS prelogin CVE-2026-119923 extracted harness.
# Verifies rungs 1/2/3, chosen-byte control (rung 4 in the extracted harness),
# the fixed control, and determinism. Exits 0 only when every check passes.
set -u
cd "$(dirname "$0")" || exit 2

CC=${CC:-gcc}
CFLAGS="-O0 -g -Wall -Wextra"
BIN=./prelogin_overflow
ASAN=./prelogin_overflow_asan

fail=0
check() {
  if eval "$2"; then
    echo "PASS $1"
  else
    echo "FAIL $1"
    fail=1
  fi
}

# --- compile -------------------------------------------------------------
$CC $CFLAGS -o "$BIN" prelogin_overflow.c || exit 2
$CC $CFLAGS -fsanitize=address -fno-omit-frame-pointer -o "$ASAN" \
  prelogin_overflow.c || exit 2

# --- rung 1: deterministic trigger --------------------------------------
r1=$($BIN rung1)
echo "$r1"
check "rung1 write extent" \
  "printf '%s' \"\$r1\" | grep -q 'length=4096 si_capacity=1024 oob_writes=3072 first_oob=1024 last_oob=4095'"
check "rung1 wire header" \
  "printf '%s' \"\$r1\" | grep -q 'wire_head=02 00 00 10 00 ff'"
check "rung1 trigger verdict" \
  "printf '%s' \"\$r1\" | grep -q 'verdict=TRIGGER'"

# --- rung 2: length chooses clobbered offsets ----------------------------
r2=$($BIN rung2)
echo "$r2"
check "rung2 length 1050 no clobber" \
  "printf '%s' \"\$r2\" | grep -q 'L=1050 oob_bytes=26 stampA_intact=1 stampB_intact=1'"
check "rung2 length 1150 clobbers A only" \
  "printf '%s' \"\$r2\" | grep -q 'L=1150 oob_bytes=126 stampA_intact=0 stampB_intact=1'"
check "rung2 length 2100 clobbers both" \
  "printf '%s' \"\$r2\" | grep -q 'L=2100 oob_bytes=1076 stampA_intact=0 stampB_intact=0'"
check "rung2 verdict" \
  "printf '%s' \"\$r2\" | grep -q 'verdict=LENGTH_CONTROL_OBSERVED'"

# --- rung 3: ASan-confirmed corruption -----------------------------------
r3log=$(mktemp)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$ASAN" rung3 >"$r3log" 2>&1
r3rc=$?
echo "rung3 rc=$r3rc"
grep -E 'rung3 length|ERROR: AddressSanitizer|WRITE of size|after 1024-byte|wire_getbytes|mode_rung3|SUMMARY: AddressSanitizer' "$r3log" | head -20
check "rung3 nonzero exit" "test $r3rc -ne 0"
check "rung3 ASan heap-buffer-overflow" \
  "grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' \"$r3log\""
check "rung3 is a WRITE" "grep -q 'WRITE of size' \"$r3log\""
check "rung3 after 1024-byte region" \
  "grep -q 'after 1024-byte region' \"$r3log\""
check "rung3 in wire_getbytes" "grep -q 'wire_getbytes' \"$r3log\""
rm -f "$r3log"

# --- rung 4: sender-chosen bytes at sender-chosen offsets ----------------
r4=$($BIN rung4)
echo "$r4"
check "rung4 chosen bytes exact" \
  "printf '%s' \"\$r4\" | grep -q 'off1100=de ad be ef ca fe ba be off2000=41 42 43 44'"
check "rung4 count and source" \
  "printf '%s' \"\$r4\" | grep -q 'chosen_bytes_written=12 offsets_exact=1 value_source=wire_packet'"
check "rung4 verdict" \
  "printf '%s' \"\$r4\" | grep -q 'verdict=CHOSEN_BYTES_AT_CHOSEN_OFFSETS'"

# --- fixed control (commit ab820bdd) -------------------------------------
rf=$($BIN fixed)
echo "$rf"
check "fixed control clean" \
  "printf '%s' \"\$rf\" | grep -q 'rc=0 oob_writes=0'"
check "fixed control verdict" "printf '%s' \"\$rf\" | grep -q 'verdict=PASS'"
# The fixed path with exact allocations must not fault under ASan.
rf_asan=$(ASAN_OPTIONS=detect_leaks=0 "$ASAN" fixed 2>&1)
echo "fixed_asan rc=$?"$'\n'"$rf_asan"
check "fixed ASan clean" \
  "printf '%s' \"\$rf_asan\" | grep -q 'verdict=PASS' && ! printf '%s' \"\$rf_asan\" | grep -q 'AddressSanitizer'"

# --- determinism ---------------------------------------------------------
sig=$(for i in 1 2 3 4 5; do $BIN rung1; done | sha256sum | cut -d' ' -f1)
sig2=$(for i in 1 2 3 4 5; do $BIN rung1; done | sha256sum | cut -d' ' -f1)
echo "determinism sha256=$sig"
check "5/5 identical" "test \"\$sig\" = \"\$sig2\""

if [ "$fail" -eq 0 ]; then
  echo "ALL CHECKS PASS"
  exit 0
fi
echo "CHECKS FAILED"
exit 1
