#!/bin/sh
# W174: does a large valid row 0 put file bytes into the row-1 OOB source?
# Builds the generator and harness from the pinned plain v3.5.2 tree, makes
# two byte-variant EXRs, dumps the 4096 source bytes at the pinned memcpy,
# and asserts the negative (no OOB offset tracks the file byte).
set -eu
cd "$(dirname "$0")/.."
G=groom
W=$G/work-large
mkdir -p "$W" "$G/evidence"
B=build-vuln-plain
S=src/openexr-3.5.2
INC="-I$B/src/lib/OpenEXRCore -I$S/src/lib/OpenEXRCore -I$B/cmake -I$B/OpenEXR_ImathIncludeCompat -I$B/_deps/imath-build/config -I$B/_deps/imath-src/src -I$S/src/lib/OpenEXR -I$S/src/lib/Iex -I$S/src/lib/IlmThread"
LIBS="$B/src/lib/OpenEXRUtil/libOpenEXRUtil*.a $B/src/lib/OpenEXR/libOpenEXR-3_5*.a $B/src/lib/OpenEXRCore/libOpenEXRCore*.a $B/src/lib/IlmThread/libIlmThread*.a $B/src/lib/Iex/libIex*.a"
IMATH_LIB=$(find "$B/_deps" -name 'libImath*.a' | sort | tr '\n' ' ')

# shellcheck disable=SC2086
gcc -g -O1 $INC "$G/groom_harness_flat.c" $LIBS $IMATH_LIB -ldeflate -lzstd -lz -lpthread -lstdc++ -lm -o "$W/groom_harness"

"$W/gen_groom_large" "$W/baseline41.exr" 0x41
"$W/gen_groom_large" "$W/baseline5a.exr" 0x5a
python3 "$G/make_poc_groom.py" "$W/baseline41.exr" "$W/poc41.exr" 0x41
python3 "$G/make_poc_groom.py" "$W/baseline5a.exr" "$W/poc5a.exr" 0x5a
sha256sum "$W"/baseline*.exr "$W"/poc*.exr

for tag in 41 41r 41r2 5a 5a2; do
  case $tag in 5a*) poc=$W/poc5a.exr ;; *) poc=$W/poc41.exr ;; esac
  gdb -q -batch \
    -ex 'set pagination off' \
    -ex 'break memcpy if $rdx == 4096' \
    -ex "run $PWD/$poc" \
    -ex "printf \"SINK n=%lu\\n\", \$rdx" \
    -ex "dump binary memory $PWD/$W/src-$tag.bin \$rsi \$rsi+4096" \
    -ex 'quit' \
    --args "$W/groom_harness" >"$W/gdb-$tag.log" 2>&1 || true
  grep -Fq 'SINK n=4096' "$W/gdb-$tag.log" || { echo "NO SINK $tag"; exit 1; }
done

python3 "$G/analyze_large.py" "$W"/src-*.bin | tee "$G/evidence/groom-large.out"
grep -Fqx 'RESULT PASS' "$G/evidence/groom-large.out"
