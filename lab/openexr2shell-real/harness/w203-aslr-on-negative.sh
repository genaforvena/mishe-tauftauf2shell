#!/bin/sh
# W203: bounded negative on removing W202's ASLR-off condition.
#
# W202 makes the unmodified pinned 3.5.2 exrcheck run
# system("touch /tmp/w202m") with setarch -R, using absolute file-carried
# heap/libc addresses.  Prediction tested here: the same PoC cannot work with
# ASLR left on, and this build offers no fixed-address, file-filled staging
# buffer that could hold the forged attribute, opaquedata and memcpy source.
# Both halves are observed below; no debugger forces a pointer or a call.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

for spec in \
    'cases/p202-memcpy-system.exr 7f3eda1b00f54b56ec75108f9012be6b035c8b6393ec1d7c2241f94be91e412e' \
    'cases/make_w202_poc.py f884e414c180bde4bb036547e65a8c5b95b269f141afb1b98a3764f6bed43402' \
    'cases/w195-pre-copy2-dump.bin f7c32f6ad820de0532396426d0ad9a8aa58440071636b03e1592cf766daffdc0' \
    'harness/w202-command.cmd 2ea315718753d90adc2a4d398a939d9ccd47a5e77b063ae33a191ff2b2cf12bc'
do
    set -- $spec
    test "$(sha256sum "$1" | cut -d' ' -f1)" = "$2"
done
test -x build-vuln-plain/bin/exrcheck
test -x build-vuln-plain/bin/exrcheck-nopie
file build-vuln-plain/bin/exrcheck-nopie | grep -q 'ELF 64-bit LSB executable'

MARKER=/tmp/w202m
RAW=$(mktemp)
trap 'rm -f "$RAW" "$MARKER"' EXIT

# Half 1: plain binaries, ASLR LEFT ON, no debugger.  Neither link reaches
# system; both fault while destroying the stale-pointer attribute list.
for NAME in exrcheck exrcheck-nopie; do
    : > "evidence/w203-plain-$NAME.out"
    I=0
    while [ "$I" -lt 5 ]; do
        I=$((I + 1))
        rm -f "$MARKER"
        RC=0
        ./build-vuln-plain/bin/$NAME -c cases/p202-memcpy-system.exr \
            > "$RAW" 2>&1 || RC=$?
        test ! -f "$MARKER"
        test "$RC" = 139
        printf 'RUN=%s rc=%s marker=ABSENT\n' "$I" "$RC" \
            >> "evidence/w203-plain-$NAME.out"
    done
done

# Half 2: attribute the plain faults under gdb, still with ASLR left on.
# The debugger stops only to read state; it sets no pointer and forces no call.
for NAME in exrcheck exrcheck-nopie; do
    rm -f "$MARKER"
    gdb -q -batch \
        -ex 'set disable-randomization off' \
        -ex 'set args -c cases/p202-memcpy-system.exr' \
        -ex 'run' -ex 'bt 3' -ex 'info registers rip' \
        ./build-vuln-plain/bin/$NAME > "$RAW" 2>&1 || true
    grep -q 'Program received signal SIGSEGV' "$RAW"
    grep -q 'exr_attr_list_destroy (ctxt=ctxt@entry=0x[0-9a-f]*' "$RAW"
    grep -q 'attributes.c:305' "$RAW"
    ! grep -q 'opaque.c:79' "$RAW"
    ! grep -q 'touch /tmp/w202m' "$RAW"
    test ! -f "$MARKER"
    CTXT=$(grep -o 'ctxt@entry=0x[0-9a-f]*' "$RAW" | head -n 1)
    test "$CTXT" != 'ctxt@entry=0x6c6f00'
    awk '
        { gsub(/ctxt@entry=0x[0-9a-f]+/, "ctxt@entry=0xHEAP") }
        { gsub(/ctxt=0x[0-9a-f]+/, "ctxt=0xHEAP") }
        { gsub(/list=0x[0-9a-f]+/, "list=0xHEAP") }
        { gsub(/list@entry=0x[0-9a-f]+/, "list@entry=0xHEAP") }
        { gsub(/cur@entry=0x[0-9a-f]+/, "cur@entry=0xHEAP") }
        { gsub(/cur=0x[0-9a-f]+/, "cur=0xHEAP") }
        { gsub(/rip[[:space:]]+0x[0-9a-f]+[[:space:]]+0x[0-9a-f]+ <exr_attr_list_destroy\+68>/,
               "rip 0xCODE <exr_attr_list_destroy+68>") }
        { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
        /Program received signal|exr_attr_list_destroy \(ctxt|attributes.c:305|rip 0xCODE/ { print }
    ' < "$RAW" > "evidence/w203-gdb-$NAME.out"
done

# Half 3: no fixed-address, file-filled staging buffer exists in this link.
# The four 64 KiB core tables below are compile-time constants; the C++
# Header stash holds compression records, not file bytes.
NM=$(mktemp)
trap 'rm -f "$RAW" "$NM" "$MARKER"' EXIT
nm -an --size-sort build-vuln-plain/bin/exrcheck-nopie > "$NM"
python3 cases/w203_globals_scan.py < "$NM" > evidence/w203-globals.out
grep -q '131072 b exrcore_dwaToLinearTable_data' evidence/w203-globals.out
grep -q '131072 b exrcore_dwaToNonLinearTable_data' evidence/w203-globals.out
grep -q '131072 b exrcore_expTable_data' evidence/w203-globals.out
grep -q '131072 b exrcore_logTable_data' evidence/w203-globals.out

CORE=src/openexr-3.5.2/src/lib/OpenEXRCore
grep -rnE '^static[[:space:]]+(uint8_t|uint16_t|char|int|float)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*\[[0-9]+\]' \
    "$CORE"/*.c > evidence/w203-core-static-arrays.out
test "$(wc -l < evidence/w203-core-static-arrays.out)" = 4
! grep -qE '\b(fread|memcpy|memmove)\b' \
    "$CORE/internal_dwa_table.c" "$CORE/internal_b44_table.c"

printf 'RESULT PASS\n'
sha256sum evidence/w203-*.out
