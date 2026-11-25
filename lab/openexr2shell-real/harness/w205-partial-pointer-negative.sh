#!/bin/sh
# W205: bounded NEGATIVE for an ASLR-on partial overwrite of the W202 victim
# pointer.  The live ctxt->free_fn is the PIE binary's internal_exr_free, not a
# libc function; system() lives in a separately randomized libc mapping.  No
# partial overwrite that preserves the random high bytes can cross the two
# mappings, and the pinned PIE binary has no system/exec-family PLT call.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

BIN=./build-vuln-plain/bin/exrcheck
LIBC=$(ldd "$BIN" | awk '/libc\.so/{print $3}')
PIE_SYM=$(nm "$BIN" | awk '$3=="internal_exr_free"{print $1}')
SYS_OFF=$(nm -D "$LIBC" | awk '$3 ~ /^system@@/{print $1; exit}')
FREE_OFF=$(nm -D "$LIBC" | awk '$3 ~ /^free@@/{print $1; exit}')
test "$PIE_SYM" = 000000000010fe50
test "$SYS_OFF" = 0000000000058750
test "$FREE_OFF" = 00000000000ade10
grep -q 'FREEFN_BEFORE=0x555555663e50' evidence/w202-chain.out
python3 -c 'assert 0x555555663e50 - 0x555555554000 == 0x10fe50'

# The pinned PIE binary has no command-executing PLT reachable from a retarget.
CMD_CALLS=$(objdump -d "$BIN" | grep -cE 'call.*<(system|__libc_system|popen|execl|execv|execve|execlp)@plt>' || true)
test "$CMD_CALLS" -eq 0

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
: > evidence/w205-partial-pointer-negative.out
{
    echo "PIE_INTERNAL_EXR_FREE=0x$PIE_SYM"
    echo "LIBC_SYSTEM=0x$SYS_OFF"
    echo "LIBC_FREE=0x$FREE_OFF"
    echo 'W202_FREEFN_BEFORE=0x555555663e50 PIE_BASE_OFF=0x555555554000'
    echo 'COMMAND_PLT_CALLS=0'
} >> evidence/w205-partial-pointer-negative.out

: > evidence/w205-aslr-maps.out
for i in 1 2; do
    gdb -q -batch -ex 'set disable-randomization off' -ex 'start' \
        -ex 'info proc mappings' "$BIN" > "$RAW" 2>&1
    PIE_BASE=$(awk '/exrcheck$/ && $1 ~ /^0x/{print $1; exit}' "$RAW")
    LIBC_BASE=$(awk '/libc\.so\.6$/ && $1 ~ /^0x/{print $1; exit}' "$RAW")
    test -n "$PIE_BASE" && test -n "$LIBC_BASE"
    echo "ASLR_ON_${i}_PIE_BASE=$PIE_BASE ASLR_ON_${i}_LIBC_BASE=$LIBC_BASE" \
        >> evidence/w205-aslr-maps.out
done
test "$(awk -F'0x' '{print $2}' evidence/w205-aslr-maps.out | sort -u | wc -l)" -eq 2
test "$(awk -F'0x' '{print $3}' evidence/w205-aslr-maps.out | sort -u | wc -l)" -eq 2
echo 'ASLR_ON_PIE_BASES_DIFFER=1 ASLR_ON_LIBC_BASES_DIFFER=1' \
    >> evidence/w205-partial-pointer-negative.out
echo 'RESULT PASS' >> evidence/w205-partial-pointer-negative.out
printf 'RESULT PASS\n'
sha256sum evidence/w205-partial-pointer-negative.out
