#!/bin/sh
# W201: bounded negative on W199's open follow-up.
#
# W199 showed the PIE-generated W197 PoC faults at attributes.c:305 when run
# against a -no-pie relink, because the file-carried absolute heap pointer in
# list->entries[0] is stale for the non-PIE heap base.  W199 left open whether a
# PoC regenerated for the non-PIE geometry could work: non-PIE code addresses
# are fixed, so only the heap address was thought to be a problem.  This check
# measures the non-PIE heap base with ASLR LEFT ENABLED across five runs and
# asserts it is not a fixed value.  A regenerated PoC would need absolute heap
# pointers that are therefore not ASLR-invariant.
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
mkdir -p evidence

POC=cases/p197-chosen-ip.exr
POCHASH=c75957f1e36ae3e03df6e79aaf5070164e0f2afe081c44bbd59542c0c16ec45a
test "$(sha256sum "$POC" | cut -d' ' -f1)" = "$POCHASH"

BUILD=build-vuln-plain
BIN=$BUILD/bin/exrcheck-nopie
LINK=$BUILD/src/bin/exrcheck/CMakeFiles/exrcheck.dir/link.txt
if [ ! -x "$BIN" ] || [ "$LINK" -nt "$BIN" ]; then
    (cd "$BUILD/src/bin/exrcheck" && \
        /usr/bin/c++ -no-pie -O2 -g -O3 -DNDEBUG \
            CMakeFiles/exrcheck.dir/main.cpp.o -o ../../../bin/exrcheck-nopie \
            ../../lib/OpenEXR/libOpenEXR-3_5.a \
            ../../lib/OpenEXRUtil/libOpenEXRUtil-3_5.a \
            ../../lib/OpenEXR/libOpenEXR-3_5.a \
            ../../lib/IlmThread/libIlmThread-3_5.a \
            ../../lib/Iex/libIex-3_5.a \
            ../../lib/OpenEXRCore/libOpenEXRCore-3_5.a \
            ../../../_deps/imath-build/src/Imath/libImath-3_2.a \
            -lm -lm /usr/lib/x86_64-linux-gnu/libdeflate.so.0 \
            /usr/lib/x86_64-linux-gnu/libzstd.so.1.5.5 -ldl) >/dev/null
fi
file "$BIN" | grep -q 'ELF 64-bit LSB executable'

RAW=$(mktemp)
trap 'rm -f "$RAW"' EXIT
: > "$RAW"
printf 'W201 non-PIE heap base with ASLR ON (5 runs)\n' >> "$RAW"
printf 'PoC sha256 %s\n' "$POCHASH" >> "$RAW"
for i in 1 2 3 4 5; do
    printf '%s\n' "--- run $i ---" >> "$RAW"
    gdb -q -batch \
        -ex "set args -c $POC" \
        -ex 'set disable-randomization off' \
        -ex 'break attributes.c:305' \
        -ex 'break opaque.c:79' \
        -ex 'run' \
        -ex 'p/x ctxt' \
        -ex 'bt 3' \
        "$BIN" >> "$RAW" 2>&1 || true
done
awk '
    { gsub(/==[0-9]+==/, "==PID==") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { print }
' < "$RAW" > evidence/w201-nopie-aslr-on.out

# Assert on the un-normalized values: five DIFFERENT heap bases (the whole
# point of the negative), none equal to the ASLR-OFF base from W199.
BASES=$(grep -c 'Breakpoint 1, exr_attr_list_destroy' evidence/w201-nopie-aslr-on.out)
test "$BASES" -eq 5
CTXTS=$(grep '^\$1 = 0x' evidence/w201-nopie-aslr-on.out | sed 's/^\$1 = //' | sort -u | wc -l)
test "$CTXTS" -eq 5
! grep -q '\$1 = 0x6c6f00' evidence/w201-nopie-aslr-on.out
! grep -q 'Breakpoint 2, exr_attr_opaquedata_destroy' evidence/w201-nopie-aslr-on.out
grep -q 'attributes.c:305' evidence/w201-nopie-aslr-on.out

# Normalize only the ASLR-varying heap pointers; non-PIE code addresses are
# deliberately kept.  Assertions above already consumed the raw values.
sed -i \
    -e 's/\(ctxt@entry=\)0x[0-9a-f][0-9a-f]*/\10xHEAP/g' \
    -e 's/\(list@entry=\)0x[0-9a-f][0-9a-f]*/\10xHEAP/g' \
    -e 's/\(ctxt=\)0x[0-9a-f][0-9a-f]*/\10xHEAP/g' \
    -e 's/\(list=\)0x[0-9a-f][0-9a-f]*/\10xHEAP/g' \
    -e 's/\(cur=\)0x[0-9a-f][0-9a-f]*/\10xHEAP/g' \
    -e 's/^\$1 = 0x[0-9a-f][0-9a-f]*/\$1 = 0xHEAP/' \
    evidence/w201-nopie-aslr-on.out
sed -i '2a DISTINCT_HEAP_BASES=5  (all different; none 0x6c6f00)' evidence/w201-nopie-aslr-on.out

printf 'RESULT PASS\n'
sha256sum evidence/w201-nopie-aslr-on.out
