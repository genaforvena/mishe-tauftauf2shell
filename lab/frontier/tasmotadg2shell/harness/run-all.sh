#!/bin/bash
# Deterministic checks for the pinned Tasmota Device Groups log-buffer sink.
# Usage: bash harness/run-all.sh   (run from anywhere)
set -uo pipefail
cd "$(dirname "$0")/.."
GEN=harness/gen
LOG=harness/evidence/run-all
mkdir -p "$LOG"
pass=0
fail=0

note() { printf '%s\n' "$*"; }
check() {
  local name="$1" rc="$2" logfile="$3" expect_rc="$4" expect="$5" forbid="${6:-}"
  if [ "$rc" != "$expect_rc" ] || ! grep -qF "$expect" "$logfile" || { [ -n "$forbid" ] && grep -qF "$forbid" "$logfile"; }; then
    note "FAIL $name rc=$rc expected=$expect_rc pattern=$expect"
    fail=$((fail + 1))
  else
    note "PASS $name"
    pass=$((pass + 1))
  fi
}

run_arm() {
  local name="$1" bin="$2" n="$3" s="$4" expect_rc="$5" expect="$6" forbid="${7:-}"
  ASAN_OPTIONS=detect_leaks=0:symbolize=1 "$GEN/$bin" "$n" "$s" > "$LOG/$name.txt" 2>&1
  check "$name" "$?" "$LOG/$name.txt" "$expect_rc" "$expect" "$forbid"
}

# Source pins must be the exact files fetched from the pinned commits.
if printf '%s  %s\n%s  %s\n' \
  70cde08eadecda129ab24c7c4369c5c742e873c4da56585b6ca7cd18bc463904 src/support_device_groups.vuln.ino \
  5ad5c1d9c34b8b2a300eb0aff76f09fc8ce8b5ba6b24536b695ea7f14024648b src/support_device_groups.fixed.ino \
  | sha256sum -c --quiet; then
  note "PASS source-pins"; pass=$((pass + 1))
else
  note "FAIL source-pins"; fail=$((fail + 1))
fi
run_arm direct-safe-vuln dgr.vuln.asan 1 0 0 'DGR_DONE log_calls=2 log_len=61' 'AddressSanitizer'
run_arm direct-safe-fixed dgr.fixed.asan 1 0 0 'DGR_DONE log_calls=2 log_len=61' 'AddressSanitizer'
run_arm wire-safe-vuln dgr.vuln.wire.asan 1 0 0 'DGR_WIRE_DONE log_calls=2 log_len=61' 'AddressSanitizer'
run_arm wire-safe-fixed dgr.fixed.wire.asan 1 0 0 'DGR_WIRE_DONE log_calls=2 log_len=61' 'AddressSanitizer'


run_arm direct-62-vuln dgr.vuln.asan 62 1 0 'DGR_DONE' 'AddressSanitizer'
run_arm direct-62-fixed dgr.fixed.asan 62 1 0 'DGR_DONE' 'AddressSanitizer'
run_arm direct-63-vuln dgr.vuln.asan 63 1 1 'WRITE of size 1' ''
run_arm direct-63-fixed dgr.fixed.asan 63 1 0 'DGR_DONE log_calls=2 log_len=511' 'AddressSanitizer'
run_arm wire-63-vuln dgr.vuln.wire.asan 63 1 1 'WRITE of size 1' ''
run_arm wire-63-fixed dgr.fixed.wire.asan 63 1 0 'DGR_WIRE_DONE log_calls=2 log_len=511' 'AddressSanitizer'
run_arm direct-65-vuln dgr.vuln.asan 65 1 1 'WRITE of size 11' ''
run_arm direct-65-fixed dgr.fixed.asan 65 1 1 'WRITE of size 11' ''
run_arm wire-65-vuln dgr.vuln.wire.asan 65 1 1 'WRITE of size 11' ''
run_arm wire-65-fixed dgr.fixed.wire.asan 65 1 1 'WRITE of size 11' ''

# GDB readback: eight wire-supplied 0x44 bytes at heap offsets 516..523.
for arm in vuln fixed; do
  f="harness/evidence/gdb-chosen-${arm}-n65.txt"
  if grep -q 'offset=515 remaining=-3' "$f" && [ "$(grep -o '0x44' "$f" | wc -l)" -ge 8 ]; then
    note "PASS gdb-chosen-$arm"; pass=$((pass + 1))
  else
    note "FAIL gdb-chosen-$arm"; fail=$((fail + 1))
  fi
done
f=harness/evidence/wire-gdb-chosen-vuln-n65.txt
if grep -q 'offset=515 remaining=-3' "$f" && [ "$(grep -o '0x44' "$f" | wc -l)" -ge 8 ]; then
  note "PASS gdb-chosen-wire-vuln"; pass=$((pass + 1))
else
  note "FAIL gdb-chosen-wire-vuln"; fail=$((fail + 1))
fi

note "RUN_ALL_OK $pass PASS / $fail FAIL"
[ "$fail" -eq 0 ]
