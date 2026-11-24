#!/usr/bin/env bash
# Read-only measurement of the control-flow bound in the pinned plain build.
# gdb reads registers and memory only: no `set`, no `call`, no forced execution.
# No source, harness, binary, pin or matrix row is changed.
# All addresses are frame-relative so the capture is invariant under ASLR.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
LOG=evidence/control-flow-bound.txt
: > "$LOG"

say() { printf '%s\n' "$*" >> "$LOG"; }

say "codebasememory2shell control-flow bound, captured $(date -u +%Y-%m-%dT%H:%M:%SZ)"
say "binary: harness-vuln-plain (gcc -std=c11 -D_DEFAULT_SOURCE -D_GNU_SOURCE -g -O1"
say "        -fno-omit-frame-pointer -w, pinned vulnerable cypher.c; see build.sh)"
say "gdb: batch, break cypher.c:4118, run 32 RETURN / run 48 RETURN; no writes"
say ""

say "=== execute_single prologue: canary loaded into rbp-0x38 ==="
objdump -d --start-address=0x14f8f --stop-address=0x14f9e harness-vuln-plain >> "$LOG"
say ""
say "=== projection loop: func_bufs[ci] passed with 0x200 (=CBM_SZ_512) stride ==="
objdump -d --start-address=0x17bd0 --stop-address=0x17c00 harness-vuln-plain >> "$LOG"
say ""
say "=== execute_single epilogue: canary check BEFORE register restore and ret ==="
objdump -d --start-address=0x18068 --stop-address=0x1808f harness-vuln-plain >> "$LOG"
say ""

cat > /tmp/cbm-w10-clean.gdb <<'GDB'
set pagination off
set confirm off
break cypher.c:4118
run 32 RETURN
printf "\n=== N=32 (in bounds) frame-relative addresses ===\n"
printf "rbp=%p  canary(rbp-0x38)=%p  saved_rip(rbp+8)=%p\n", $rbp, $rbp-0x38, $rbp+8
x/2gx $rbp-0x38
x/gx $rbp+8
quit
GDB
say "=== gdb N=32 clean ==="
gdb -q -batch -x /tmp/cbm-w10-clean.gdb ./harness-vuln-plain >> "$LOG" 2>&1 || true
say ""

cat > /tmp/cbm-w10-oob.gdb <<'GDB'
set pagination off
set confirm off
break cypher.c:4118
run 48 RETURN
printf "\n=== N=48 (OOB) frame-relative addresses ===\n"
printf "rbp=%p  func_bufs[38]=rbp-0x40=%p  canary=rbp-0x38=%p  saved_rip=rbp+8=%p\n", $rbp, $rbp-0x40, $rbp-0x38, $rbp+8
printf "=== chosen bytes at func_bufs[38] (canary is payload offset 8) ===\n"
x/12gx $rbp-0x40
printf "=== saved registers restored by the epilogue ===\n"
x/6gx $rbp-0x28
quit
GDB
say "=== gdb N=48 OOB ===="
gdb -q -batch -x /tmp/cbm-w10-oob.gdb ./harness-vuln-plain >> "$LOG" 2>&1 || true
say ""

say "=== plain 48-item process result ==="
(./harness-vuln-plain 48 RETURN 2>&1 || true) >> "$LOG"
say ""
say "Frame-relative arithmetic (ASLR-invariant):"
say "  func_bufs[0] = rbp-0x4c40; item stride 0x200; func_bufs[38] = rbp-0x40."
say "  canary       = rbp-0x38 = func_bufs[38]+8  -> payload offset 8."
say "  saved rip    = rbp+8    = func_bufs[38]+0x48 -> payload offset 0x48."
say "  saved regs   = rbp-0x28..rbp+0  (rbx,r12,r13,r14,r15,rbp)."
say "The 70-byte property copy spans offsets 0..0x45: it overwrites the canary"
say "and all six saved registers but stops two bytes short of saved rip."
say "The epilogue checks the canary at 0x1806c and branches to __stack_chk_fail"
say "before restoring those registers at 0x18084-0x1808d or returning at 0x1808e."
say "project_item caps the copy at strlen(raw) <= 511; a C string cannot put 0x00"
say "at offset 8 without ending there, so no longer value can preserve the"
say "canary's zero low byte while reaching saved rip. Control-flow hijack is a"
say "structural negative for this compiler/build; grade stays rungs 1-4."
sha256sum "$LOG"
