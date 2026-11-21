#!/bin/sh
# Reproducible build for the pinned ClassiCube Png_Decode ASan harness.
# NO network. Pinned sources are extracted from the committed tarballs in pins/.
#
# Real pinned sources compiled verbatim (no edits, no copied logic):
#   src/Bitmap.c   -> Png_Decode, Png_Reconstruct (the vulnerable code under test)
#   src/Deflate.c  -> Inflate_Process/Inflate_StreamRead (the overflow write sink)
#   src/Stream.c   -> Stream_ReadonlyMemory/ReadonlyPortion (real chunk stream plumbing)
#
# Stubs in stubs.c, and why each cannot fake the claimed primitive:
#   Mem_TryAlloc/Mem_Alloc/Mem_Free -> malloc/free. Deliberately exact-size so
#       ASan reports pin to the pinned allocation at Bitmap.c:459. They only
#       supply memory; they perform no PNG/DEFLATE parsing or reconstruction.
#   Mem_Copy/Mem_Set -> memcpy/memset, used by the real Inflate_Process.
#   Mem_Equal, Mem_ReadU32_BE/LE, TempMem_Alloc -> trivial pure helpers needed by
#       real code; cannot write out of bounds on their own.
#   Process_Abort2, Logger_DoAbort, Logger_FailToStart -> abort on impossible
#       internal states; never reached in these tests.
#   (String_Init is static inline in the pinned header, not stubbed.)
# -DCC_BUILD_MANUAL disables platform auto-detection; -ffunction-sections and
# --gc-sections drop unreachable pinned functions (encoders, ZIP, filesystems)
# that would otherwise need irrelevant platform shims. Neither affects the
# compiled Png_Decode/Png_Reconstruct/Inflate_Process bodies.
set -eu
cd "$(dirname "$0")"
mkdir -p src
for V in 1.3.9 1.4.0; do
  [ -d "src/ClassiCube-$V" ] || tar xzf "pins/classicube-$V.tar.gz" -C src
done
COMMON="-fsanitize=address -g -O0 -std=c11 -ffunction-sections -fdata-sections -Wl,--gc-sections -DCC_BUILD_MANUAL"
for V in 1.3.9 1.4.0; do
  SRC="src/ClassiCube-$V/src"
  OUT="asm_$(printf '%s' "$V" | tr -d '.')"
  clang $COMMON -I"$SRC" harness.c stubs.c \
    "$SRC/Bitmap.c" "$SRC/Deflate.c" "$SRC/Stream.c" -o "$OUT"
  echo "built $OUT from $SRC"
done
