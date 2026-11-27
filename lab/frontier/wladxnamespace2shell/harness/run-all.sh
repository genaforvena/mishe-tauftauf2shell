#!/bin/sh
# Drive the real wlalink binary with crafted object files; all checks are local.
set -eu
cd "$(dirname "$0")"
mkdir -p evidence
PASS=0
FAIL=0
ok() { echo "PASS $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL $1"; FAIL=$((FAIL+1)); }
expect() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }

python3 generate-inputs.py
if sha256sum -c INPUT_SHA256SUMS >/dev/null 2>&1; then ok "input pins"; else bad "input pins"; fi

V=../build-vuln-asan/binaries
F=../build-fixed-asan/binaries
P=../build-vuln-plain/binaries
A="ASAN_OPTIONS=detect_leaks=0"

env $A "$V/wla-6502" -o attack.o attack.s
env $A "$V/wla-6502" -o attack-large.o attack-large.s
env $A "$V/wla-6502" -o attack-pattern.o attack-pattern.s
env $A "$V/wla-6502" -o safe.o safe.s
env $A "$F/wla-6502" -o attack-pattern-fixed.o attack-pattern.s
env $A "$F/wla-6502" -o safe-fixed.o safe.s

set +e
env $A "$V/wlalink" -b linkfile out-vuln.bin > evidence/vuln-asan.raw 2>&1; RV=$?
env $A "$V/wlalink" -b linkfile-safe out-safe.bin > evidence/vuln-safe.raw 2>&1; RS=$?
env $A "$F/wlalink" -b linkfile-pattern-fixed out-fixed.bin > evidence/fixed-asan.raw 2>&1; RF=$?
env $A "$F/wlalink" -b linkfile-safe-fixed out-fixed-safe.bin > evidence/fixed-safe.raw 2>&1; RFS=$?
"$P/wlalink" -b linkfile-large out-large.bin > evidence/plain-large.raw 2>&1; RL=$?
set -e

grep -o 'ERROR: AddressSanitizer: stack-buffer-overflow' evidence/vuln-asan.raw > evidence/vuln-asan.log
grep -o 'WRITE of size 1' evidence/vuln-asan.raw >> evidence/vuln-asan.log
grep -o 'analyze.c:2155' evidence/vuln-asan.raw >> evidence/vuln-asan.log
printf 'VULN_ASAN_RC=%s\nFIXED_ASAN_RC=%s\nSAFE_VULN_RC=%s\nSAFE_FIXED_RC=%s\nPLAIN_LARGE_RC=%s\nFIXED_OUT_BYTES=%s\n' "$RV" "$RF" "$RS" "$RFS" "$RL" "$(wc -c < out-fixed.bin)" > evidence/controls.log

expect 'vulnerable ASan rc=1' '[ "$RV" -eq 1 ]'
expect 'ASan stack-buffer-overflow' "grep -q 'stack-buffer-overflow' evidence/vuln-asan.log"
expect 'ASan WRITE size 1' "grep -q 'WRITE of size 1' evidence/vuln-asan.log"
expect 'fault at pinned analyze.c:2155' "grep -q 'analyze.c:2155' evidence/vuln-asan.log"
expect 'fixed ASan rc=0' '[ "$RF" -eq 0 ]'
expect 'fixed ASan no report' "! grep -q 'AddressSanitizer' evidence/fixed-asan.raw"
expect 'vulnerable safe input rc=0' '[ "$RS" -eq 0 ]'
expect 'vulnerable safe no report' "! grep -q 'AddressSanitizer' evidence/vuln-safe.raw"
expect 'fixed safe input rc=0' '[ "$RFS" -eq 0 ]'
expect 'plain large-overflow negative' '[ "$RL" -ne 0 ]'

gdb -q -batch -ex 'set pagination off' -ex 'set disable-randomization on' \
  -ex 'break analyze.c:2156' -ex 'run -b linkfile-pattern out-pattern.bin' \
  -ex 'printf "BP_HIT=1\n"' \
  -ex 'printf "V256=%02x V260=%02x V269=%02x V270=%02x\n", buf[256], buf[260], buf[269], buf[270]' \
  -ex 'x/40bx buf+252' -ex 'x/4gx buf+272' -ex 'continue' \
  --args "$P/wlalink" > evidence/gdb-pattern.raw 2>&1
grep -E 'BP_HIT=1|V256=' evidence/gdb-pattern.raw > evidence/gdb-pattern.log
grep -o 'exited normally' evidence/gdb-pattern.raw >> evidence/gdb-pattern.log
expect 'GDB breakpoint reached' "grep -q 'BP_HIT=1' evidence/gdb-pattern.log"
expect 'chosen 0x44 at buf+256,260,269' "grep -q 'V256=44 V260=44 V269=44 V270=00' evidence/gdb-pattern.log"
expect 'plain pattern link completes' "grep -q 'exited normally' evidence/gdb-pattern.log"

if sha256sum -c evidence/SHA256SUMS >/dev/null 2>&1; then ok 'evidence pins'; else bad 'evidence pins'; fi
if sha256sum -c INPUT_SHA256SUMS >/dev/null 2>&1; then ok 'input pins after run'; else bad 'input pins after run'; fi

echo "RUN_ALL_OK $PASS PASS / $FAIL FAIL"
[ "$FAIL" -eq 0 ]
