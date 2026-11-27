#!/usr/bin/env bash
# W336: bounded no-shim harness run answering one question: does the pinned
# extraction loop ever READ indexes past its wrapped data_size? Nothing is
# patched; the only instrumentation is GDB watchpoints and breakpoints.
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p out harness/evidence
gcc -O0 -g -I. -DPLAIN_MODE -o out/plain-336 harness/driver.c -lz
gdb -q -batch -x harness/gdb-extract-336.cmd --args out/plain-336 attack \
  > harness/evidence/w336-extract-full.log 2>&1 || true

echo "=== W336 GDB transcript (filtered) ==="
grep -E 'W336|Hardware watchpoint|exited normally|exited with code|Breakpoint [0-9]+,|Program received' \
  harness/evidence/w336-extract-full.log
