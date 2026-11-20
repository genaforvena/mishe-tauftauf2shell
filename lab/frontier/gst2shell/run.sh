#!/usr/bin/env bash
# Driver for the GStreamer rtpL16depay CVE-2026-111183 extracted harness.
# Verifies rungs 1/2/3, the honest rung-4 negative, the fixed control and
# determinism. Exits 0 only when every check passes.
set -u
cd "$(dirname "$0")" || exit 2

CC=${CC:-gcc}
CFLAGS="-O0 -g -Wall -Wextra"
BIN=./rtp_channels_overflow
ASAN=./rtp_channels_overflow_asan

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
$CC $CFLAGS -o "$BIN" rtp_channels_overflow.c || exit 2
$CC $CFLAGS -fsanitize=address -fno-omit-frame-pointer -o "$ASAN" \
  rtp_channels_overflow.c || exit 2

# --- rung 1: deterministic trigger --------------------------------------
r1=$($BIN rung1)
echo "$r1"
check "rung1 write extent" \
  "printf '%s' \"\$r1\" | grep -q 'channels=1000 position_capacity=64 oob_writes=936 first_oob=256 last_oob=3999'"
check "rung1 counted bytes" \
  "printf '%s' \"\$r1\" | grep -q 'counted_none_bytes=3744'"
check "rung1 trigger verdict" \
  "printf '%s' \"\$r1\" | grep -q 'verdict=TRIGGER'"

# --- rung 2: chosen length/offset clobber control ------------------------
r2=$($BIN rung2)
echo "$r2"
check "rung2 before stamps intact" \
  "printf '%s' \"\$r2\" | grep -q 'before off1_abcd=1 off2_cdab=1'"
check "rung2 channels200 partial" \
  "printf '%s' \"\$r2\" | grep -q 'channels200 off1_abcd=0 off2_cdab=1 oob_bytes=544'"
check "rung2 channels1000 full" \
  "printf '%s' \"\$r2\" | grep -q 'channels1000 off1_abcd=0 off2_cdab=0 oob_bytes=3744'"
check "rung2 verdict" \
  "printf '%s' \"\$r2\" | grep -q 'verdict=LENGTH_CONTROL_OBSERVED'"

# --- rung 3: ASan-confirmed corruption -----------------------------------
r3log=$(mktemp)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$ASAN" rung3 exact >"$r3log" 2>&1
r3rc=$?
echo "rung3 rc=$r3rc"
grep -E 'rung3 channels|ERROR: AddressSanitizer|WRITE of size|after .* object|create_default|SUMMARY: AddressSanitizer' "$r3log" | head -20
check "rung3 nonzero exit" "test $r3rc -ne 0"
check "rung3 ASan heap-buffer-overflow" \
  "grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' \"$r3log\""
check "rung3 is a WRITE" "grep -q 'WRITE of size' \"$r3log\""
check "rung3 after 256-byte region" \
  "grep -q 'after 256-byte region' \"$r3log\""
check "rung3 in vuln_create_default" \
  "grep -q 'vuln_create_default' \"$r3log\""
rm -f "$r3log"

# --- rung 4: honest negative ---------------------------------------------
r4=$($BIN rung4)
echo "$r4"
check "rung4 constant write only" \
  "printf '%s' \"\$r4\" | grep -q 'chosen_bytes_written=0 written_value_constant=NONE(0)'"
check "rung4 honest NOT" \
  "printf '%s' \"\$r4\" | grep -q 'verdict=NOT_DEMONSTRATED'"

# --- fixed control -------------------------------------------------------
rf=$($BIN fixed)
echo "$rf"
check "fixed control clean" "printf '%s' \"\$rf\" | grep -q 'oob_writes=0 verdict=PASS'"

# --- determinism ---------------------------------------------------------
sig=$(for i in 1 2 3 4 5; do $BIN rung1; done | sha256sum | cut -d' ' -f1)
echo "determinism sha256=$sig"
check "5/5 identical" \
  "test \"\$sig\" = \"$(for i in 1 2 3 4 5; do $BIN rung1; done | sha256sum | cut -d' ' -f1)\""

if [ "$fail" -eq 0 ]; then
  echo "ALL CHECKS PASS"
  exit 0
fi
echo "CHECKS FAILED"
exit 1
