#!/bin/sh
# W15: clean-archive indirect-branch survey of process_udp in a THIRD build:
# pinned vulnerable n2n, gcc -O2, non-PIE. W12 already covered clang -O2
# non-PIE and gcc -O1 PIE. A poisonable call target would need an indirect
# call in this function; indirect jumps must be bounded switch tables.
# Build-only, loopback-free; gdb and the live supernode are not involved.
set -u
HERE=$(cd "$(dirname "$0")" || exit 1; pwd)
N2N=$(cd "$HERE/.." || exit 1; pwd)
TARBALL=$N2N/provision/n2n-vuln.tar.gz
EVID=$HERE/evidence
WORK=${TMPDIR:-/tmp}/n2n2shell-w15.$$
PASS=0
FAIL=0
mkdir -p "$WORK/src" || exit 1
trap 'rm -rf "$WORK"' EXIT HUP INT TERM

check() {
    if [ "$2" -eq 0 ]; then
        echo "PASS $1"
        PASS=$((PASS + 1))
    else
        echo "FAIL $1"
        FAIL=$((FAIL + 1))
    fi
}

tar xzf "$TARBALL" -C "$WORK/src" || exit 1
SRC=$WORK/src/n2n-dc7324af16b2ff3e2b22961e7d8dffcb14f3f6ff
(cd "$SRC" && sh autogen.sh &&
    CC=gcc CFLAGS="-g -O2 -fno-omit-frame-pointer -no-pie" \
    LDFLAGS="-no-pie" ./configure &&
    make -j4 supernode) >"$EVID/w15-build.log" 2>&1
check 01-gcc-o2-non-pie-build "$?"
[ -x "$SRC/supernode" ] || { echo "RESULT $PASS PASS / $FAIL FAIL"; exit 1; }

# gcc -O2 renames process_udp to process_udp.isra.0; use the exact symbol
# extent so neighbouring functions cannot skew the branch count.
readelf -n "$SRC/supernode" >"$EVID/w15-readelf.log" 2>&1
readelf -SW "$SRC/supernode" >"$EVID/w15-sections.log" 2>&1
LINE=$(nm -an "$SRC/supernode" | grep ' process_udp.isra.0$')
check 02-process-udp-symbol "$?"
ADDR=$(echo "$LINE" | cut -d' ' -f1)
SIZE=$(readelf -sW "$SRC/supernode" | grep ' process_udp.isra.0$' | tr -s ' ' | cut -d' ' -f4)
[ -n "$ADDR" ] && [ -n "$SIZE" ]
check 03-symbol-extent "$?"

objdump -d --start-address="0x$ADDR" --stop-address="$((0x$ADDR + SIZE))" \
    "$SRC/supernode" >"$EVID/w15-process-udp.asm" 2>&1
check 04-disassembly "$?"

CALLN=$(grep -cE 'call[[:space:]]+\*' "$EVID/w15-process-udp.asm")
[ "$CALLN" -eq 0 ]
check 05-zero-indirect-calls "$?"
echo "INFO indirect_calls=$CALLN"

JMPN=$(grep -cE 'jmp[[:space:]]+\*' "$EVID/w15-process-udp.asm")
[ "$JMPN" -eq 3 ]
check 06-three-indirect-jumps "$?"
echo "INFO indirect_jumps=$JMPN"

# Each jump is preceded by a `cmp $0xb; ja` guard and an lea into .rodata.
OK=0
for JMPLINE in $(grep -nE 'jmp[[:space:]]+\*' "$EVID/w15-process-udp.asm" | cut -d: -f1); do
    START=$((JMPLINE - 6))
    [ "$START" -lt 1 ] && START=1
    CTX=$(sed -n "${START},${JMPLINE}p" "$EVID/w15-process-udp.asm")
    if echo "$CTX" | grep -q 'cmp.*\$0xb' &&
       echo "$CTX" | grep -q 'ja ' &&
       echo "$CTX" | grep -q '# 4254'; then
        OK=$((OK + 1))
    fi
done
[ "$OK" -eq "$JMPN" ] && [ "$JMPN" -gt 0 ]
check 07-all-jumps-bounded-rodata-tables "$?"
echo "INFO bounded_jumps=$OK"
grep -E 'cmp.*\$0xb|# 4254|jmp[[:space:]]+\*' "$EVID/w15-process-udp.asm" \
    >"$EVID/w15-switch-tables.txt"

echo "RESULT $PASS PASS / $FAIL FAIL"
echo "RAW $EVID/w15-{build,readelf,sections,process-udp.asm,switch-tables.txt}"
echo "INFO build_id=$(grep -A1 'Build ID' "$EVID/w15-readelf.log" | grep -o '[0-9a-f]\{40\}')"
[ "$FAIL" -eq 0 ]
