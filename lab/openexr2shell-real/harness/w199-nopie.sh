#!/bin/sh
# W199: bounded negative on the ASLR-on route past W197.
#
# Idea: relink the pinned 3.5.2 exrcheck -no-pie so code addresses are fixed.
# Observation: that also changes the heap base, so the file-carried absolute
# heap pointers in p197-chosen-ip.exr are stale.  attr_destroy() faults at
# attributes.c:305 before reaching the file-chosen destructor at opaque.c:79.
# This does not make the W197 chosen IP work with ASLR on; it is preserved as
# a negative so the route is not re-spent on.
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
gdb -q -batch \
    -ex "set args -c $POC" \
    -ex 'set disable-randomization on' \
    -ex 'break opaque.c:79' \
    -ex 'run' \
    -ex 'info registers rip' \
    -ex 'bt 3' \
    "$BIN" > "$RAW" 2>&1 || true

grep -q 'Breakpoint 1 at' "$RAW"
grep -q 'Program received signal SIGSEGV' "$RAW"
grep -q 'exr_attr_list_destroy (ctxt=ctxt@entry=0x6c6f00' "$RAW"
grep -q 'attributes.c:305' "$RAW"
! grep -q 'opaque.c:79.*exr_attr_opaquedata_destroy' "$RAW"

awk '
    { gsub(/==[0-9]+==/, "==PID==") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell\/lab\/openexr2shell-real/, "LAB") }
    { gsub(/\/home\/mesh-home\/mishe-tauftauf2shell/, "SITE") }
    { print }
' < "$RAW" > evidence/w199-nopie.out
grep -q 'ctxt=ctxt@entry=0x6c6f00' evidence/w199-nopie.out
grep -q 'attributes.c:305' evidence/w199-nopie.out

printf 'RESULT PASS\n'
sha256sum evidence/w199-nopie.out
