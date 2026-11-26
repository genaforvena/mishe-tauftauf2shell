#!/usr/bin/env bash
# Measure whether a naturally adjacent pointer is semantically dereferenced
# after the real rpm2cpio symlink-size overflow. No LD_PRELOAD, no groom.
set -u
cd "$(dirname "$0")"
out=natural-continue/raw
mkdir -p "$out"
vuln=../build-vuln-plain/tools/rpm2cpio
[ -x "$vuln" ] || { echo "missing $vuln"; exit 1; }

pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass + 1)); }
bad() { echo "FAIL $1"; fail=$((fail + 1)); }

# 20 plain continuations past the copy: no crash, no debugger-forced exit.
for i in $(seq 1 20); do
    timeout 25 gdb -q -batch -x layout-continue.gdb "$vuln" \
        > "$out/continue-$i.log" 2>&1
    log="$out/continue-$i.log"
    if grep -q 'AFTER_BUF=' "$log" && \
       grep -q 'exited with code 01' "$log" && \
       ! grep -q 'SIGSEGV' "$log"; then
        ok "continue-$i exits 1 without a fault"
    else
        bad "continue-$i"
    fi
done

# 20 read-watchpoint runs: count natural pointer-bearing adjacency and
# record any read of the overwritten qword. The watchpoint is not evidence
# of a semantic dereference by itself (it also fires with nil adjacency).
ptr=0
watch=0
for i in $(seq 1 20); do
    log="$out/rwatch-$i.log"
    timeout 25 gdb -q -batch -x rwatch-after.gdb "$vuln" \
        > "$log" 2>&1
    if grep -q 'AFTER_BUF=' "$log"; then
        ok "rwatch-$i reached the copy"
    else
        bad "rwatch-$i"
    fi
    if ! grep -q 'ADJacent=(nil)' "$log"; then
        ptr=$((ptr + 1))
    fi
    if grep -q 'Hardware read watchpoint' "$log"; then
        watch=$((watch + 1))
    fi
done

# 12 target inspections: identify what the natural pointer pointed to.
iptr=0
for i in $(seq 1 12); do
    log="$out/inspect-$i.log"
    timeout 25 gdb -q -batch -x inspect-adjacent.gdb "$vuln" \
        > "$log" 2>&1
    if grep -q 'AFTER_BUF=' "$log"; then
        ok "inspect-$i reached the copy"
    else
        bad "inspect-$i"
    fi
    if ! grep -q 'ADJacent=(nil)' "$log"; then
        iptr=$((iptr + 1))
    fi
done

echo "NATURAL_POINTER_ADJACENCY=$ptr/20 READ_WATCHPOINT=$watch/20 INSPECT_POINTER=$iptr/12"
echo "NATURAL_DEREF_PASS=$pass NATURAL_DEREF_FAIL=$fail"
[ "$fail" -eq 0 ]
