#!/bin/sh
# W322: resolve the W321 libgobject caller frames offline and print the pinned
# GLib source that identifies the heap object at indexes+272. No live plug-in
# run, no network, no heap or plugin bytes changed. Replay from a clean archive:
#   bash lab/frontier/gimpjif2shell/live/resolve-w322-type.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../../../.." && pwd)
CHAIN="$HERE/evidence/w321-allocsite-chain.log"
W317="$HERE/evidence/w317-nameobj.log"
PINS="$ROOT/lab/frontier/gimpjif2shell/pins/glib-2.84-gtype-excerpts.txt"
APP=${GIMPJIF_APPIMAGE_ROOT:-/tmp/gimpjif-appimage-w316/squashfs-root}
LIB="$APP/usr/lib/x86_64-linux-gnu/libgobject-2.0.so.0"
GLIB="$APP/usr/lib/x86_64-linux-gnu/libglib-2.0.so.0"

for F in "$CHAIN" "$W317" "$PINS" "$LIB" "$GLIB"; do
  [ -f "$F" ] || { echo "W322 MISSING $F"; exit 1; }
done

# Refuse to "resolve" addresses that are not the exact logged W321 evidence.
grep -Fq 'W321 CHAIN +272 ? 0x7ffff7a50236 [No symbol matches 0x7ffff7a50236.]' "$CHAIN"
grep -Fq 'W321 CHAIN +304 ? 0x7ffff7a502bd [No symbol matches 0x7ffff7a502bd.]' "$CHAIN"
grep -Fq 'W321 CHAIN +272 g_type_register_dynamic 0x7ffff7a55999 [g_type_register_dynamic + 201' "$CHAIN"
grep -Fq '=== W317 word+272 @0x5555557037f0 = 0x0000000000000001' "$W317"
grep -Fq '=== W317 word+280 @0x5555557037f8 = 0x0000555555703810' "$W317"
grep -Fq '=== W317 word+304 @0x555555703810 = 0x00007fff00000001' "$W317"

SYM=$(nm -D --defined-only "$LIB" | awk '$3 == "g_type_register_dynamic" { print $1; exit }')
BASE=$((0x7ffff7a55999 - 201 - 0x$SYM))
OFF272=$((0x7ffff7a50236 - BASE))
OFF304=$((0x7ffff7a502bd - BASE))

printf 'W322 libgobject SHA256 %s\n' "$(sha256sum "$LIB" | awk '{print $1}')"
printf 'W322 libglib SHA256 %s\n' "$(sha256sum "$GLIB" | awk '{print $1}')"
printf 'W322 g_type_register_dynamic symbol-offset=%s load-base=%#x frame+272=%#x frame+304=%#x\n' \
  "$SYM" "$BASE" "$OFF272" "$OFF304"
printf 'W322 bundled libglib version .rodata (micro, minor, major):\n'
objdump -s --start-address=0x1335cc --stop-address=0x1335d8 "$GLIB"

printf 'W322 disassembly around the +272 return site (g_malloc0 of 16 bytes):\n'
objdump -d --start-address=$((OFF272 - 0x16)) --stop-address=$((OFF272 + 0x50)) "$LIB"
printf 'W322 disassembly around the +304 return site (g_realloc_n of 1 QData):\n'
objdump -d --start-address=$((OFF304 - 0x1f)) --stop-address=$((OFF304 + 0x10)) "$LIB"
printf 'W322 g_return_if_fail domain/function strings for type_add_flags_W:\n'
objdump -s --start-address=0x4706c --stop-address=0x47080 "$LIB"
objdump -s --start-address=0x4cbd0 --stop-address=0x4cbf0 "$LIB"
objdump -s --start-address=0x514a0 --stop-address=0x514b0 "$LIB"

printf 'W322 pinned GLib 2.84 gtype.c excerpts (TypeNode/GData/QData/type_add_flags_W):\n'
cat "$PINS"
