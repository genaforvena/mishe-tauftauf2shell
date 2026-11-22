#!/bin/sh
# Build the EoE harness against both hash-pinned SOES releases.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
mkdir -p "$ROOT/build"
for V in 3.2.0 3.2.1; do
   SRC="$ROOT/src/SOES-$V"
   INC="-I$SRC -I$SRC/soes -I$SRC/soes/include/sys/gcc -I$SRC/applications/linux_lan9252demo"
   clang -g -O0 -fsanitize=address $INC \
      "$ROOT/harness/eoe_overflow.c" "$SRC/soes/esc_eoe.c" \
      -o "$ROOT/build/eoe_asan_$V"
   echo "built $ROOT/build/eoe_asan_$V"
   clang -g -O0 $INC \
      "$ROOT/harness/eoe_overflow.c" "$SRC/soes/esc_eoe.c" \
      -o "$ROOT/build/eoe_plain_$V"
   echo "built $ROOT/build/eoe_plain_$V"
done
