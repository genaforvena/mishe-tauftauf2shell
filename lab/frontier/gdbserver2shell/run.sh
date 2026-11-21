#!/usr/bin/env bash
# Replay driver — gdbserver qtdpsrc extracted harness (CVE-2026-121997).
set -uo pipefail
OUT=${1:-out}
mkdir -p "$OUT"
DIR=$(cd "$(dirname "$0")" && pwd)
C="$DIR/qtdpsrc_overflow.c"
gcc -O0 -g -o "$OUT/qtdpsrc" "$C" || exit 2
gcc -O0 -g -fsanitize=address -o "$OUT/qtdpsrc_asan" "$C" || exit 2

{
  echo "== rung1"; "$OUT/qtdpsrc" rung1; echo "rung1_rc=$?"
  echo "== rung2"; "$OUT/qtdpsrc" rung2; echo "rung2_rc=$?"
  echo "== rung4"; "$OUT/qtdpsrc" rung4; echo "rung4_rc=$?"
  echo "== fixed"; "$OUT/qtdpsrc" fixed; echo "fixed_rc=$?"
  echo "== rung3"; ASAN_OPTIONS=detect_leaks=0 "$OUT/qtdpsrc_asan" rung3 2>&1; echo "rung3_rc=$?"
} > "$OUT/run.log" 2>&1

rc=0
check() { if grep -qF "$1" "$OUT/run.log"; then echo "PASS $2"; else echo "FAIL $2"; rc=1; fi; }
check 'RUNG1 declared=8 actual=32 oob_writes=23 first_oob=9 last_oob=31' rung1
check 'RUNG2 delta=32 declared=8 actual=48 oob_writes=39 fn_changed=1 stamp_changed=1' rung2
check 'rung1_rc=0' rung1_rc
check 'rung2_rc=0' rung2_rc
check 'MARKER EXECUTED: chosen td_ta_map_lwp2thr_p reached' rung4_marker
check 'RUNG4 chosen_value_control=ESTABLISHED-IN-HARNESS' rung4_control
check 'rung4_rc=0' rung4_rc
check 'FIXED REJECT: actual > declared' fixed_reject
check 'FIXED src_null=1 oob_writes=0' fixed_control
check 'fixed_rc=0' fixed_rc
check 'ERROR: AddressSanitizer: heap-buffer-overflow' asan_report
check 'WRITE of size 1' asan_write
check 'in hex2bin' asan_frame
check 'in cmd_qtdpsrc' asan_caller

echo "sha256=$(sha256sum "$OUT/run.log" | cut -d' ' -f1)"
if [ "$rc" -eq 0 ]; then echo "ALL CHECKS PASS rc 0"; else echo "CHECKS FAILED rc $rc"; fi
exit "$rc"
