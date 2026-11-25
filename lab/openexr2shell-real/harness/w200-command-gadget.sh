#!/bin/sh
# W200: one-command replay of the bounded benign-command gadget search.
set -eu
LAB=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$LAB"
test -x build-vuln-plain/bin/exrcheck
OUT=evidence/w200-command-gadgets.out
python3 cases/w200_gadget_scan.py "$LAB" > "$OUT"

# The scan must have parsed real module text, and no command-launch route may
# appear in the classes the W197 call shape could reach.
grep -Eq '^instructions=[1-9][0-9]*$' "$OUT"
for key in command_imports rsi_to_rdi_then_command_branch; do
    if ! grep -q "^${key}=0 " "$OUT"; then
        echo "FAIL: $key is not empty"
        exit 1
    fi
done
if ! grep -q '^execve_immediate_in_windows=0$' "$OUT"; then
    echo "FAIL: an execve syscall gadget is present"
    exit 1
fi
# The only indirect-call site found on this host uses r12 (not a W197
# controlled register); assert that no rsi/rip-relative base appears.
if grep '^rsi_to_rdi_then_indirect_call=' "$OUT" | grep -Eq '\(%r(si|di|dx)\)'; then
    echo "FAIL: indirect call through a controlled register"
    exit 1
fi

HASH=$(sha256sum "$OUT" | cut -d' ' -f1)
grep -E '^(instructions|command_imports|direct_command_branches|rsi_to_rdi_then_command_branch|rsi_to_rdi_then_syscall|execve_immediate_in_windows|rsi_to_rdi_then_indirect_call)=' "$OUT" | cut -c1-160
printf 'RESULT PASS rc=0 sha256=%s\n' "$HASH"
