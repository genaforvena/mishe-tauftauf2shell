#!/usr/bin/env bash
# Real lwext4 mount-path replay for CVE-2025-71473 / CVE-2025-71474.
# Requires the provisioned upstream clone at real/lwext4-upstream (see README
# in PROVENANCE.md); builds both pinned trees under ASan, crafts ext4 images
# with lwext4's own ext4_mkfs() and checks vulnerable/fixed/safe controls.
# Loopback file block device only; no network or command execution.
set -u
cd "$(dirname "$0")"
pass=0
fail=0
ok()  { echo "PASS $1"; pass=$((pass+1)); }
bad() { echo "FAIL $1"; fail=$((fail+1)); }
has() { grep -qF "$2" "$1"; }

VULN_PIN=890484c72dbb321535127625c3686e51f1f424b9
FIX_PIN=b9c842f168e6044bd03fe34e1237eda33c299908

echo "== pinned upstream =="
[ "$(git -C real/lwext4-upstream rev-parse v1.0.0)" = "$VULN_PIN" ] \
    && ok "vulnerable commit v1.0.0" || bad "vulnerable commit v1.0.0"
[ "$(git -C real/lwext4-upstream rev-parse "$FIX_PIN^{commit}")" = "$FIX_PIN" ] \
    && ok "fixed commit b9c842f1" || bad "fixed commit b9c842f1"

echo "== real ASan builds =="
CFLAGS='-fsanitize=address -g -O0 -fno-omit-frame-pointer'
for variant in vuln fixed; do
    cmake -S "real/lwext4-upstream/$variant" -B "real/build-$variant-asan" \
        -DLIB_ONLY=1 -DCMAKE_C_FLAGS="$CFLAGS" > "real/evidence/build-$variant.log" 2>&1 \
        && cmake --build "real/build-$variant-asan" -j4 \
            >> "real/evidence/build-$variant.log" 2>&1 \
        && ok "cmake build $variant" || bad "cmake build $variant"
done
compile() {
    variant=$1
    extra=""
    inc="-Ireal/lwext4-upstream/$variant/include -Ireal/lwext4-upstream/$variant/blockdev/linux -Ireal/build-$variant-asan/include"
    src="real/lwext4-upstream/$variant/blockdev/linux/ext4_filedev.c"
    if [ "$variant" = fixed ]; then
        extra=-DREAL_FIXED
        src="real/lwext4-upstream/$variant/blockdev/linux/file_dev.c"
    fi
    gcc $CFLAGS $extra $inc real/mount_driver.c "$src" \
        -Wl,--start-group "real/build-$variant-asan/src/liblwext4.a" \
        "real/build-$variant-asan/blockdev/libblockdev.a" -Wl,--end-group \
        -o "real/driver-$variant" > "real/evidence/compile-$variant.log" 2>&1
}
compile vuln && ok "compile driver-vuln" || bad "compile driver-vuln"
compile fixed && ok "compile driver-fixed" || bad "compile driver-fixed"

echo "== crafted images =="
python3 -c "open('real/image-base.ext4','wb').truncate(16*1024*1024)" \
    && ok "pristine image allocation" || bad "pristine image allocation"
ASAN_OPTIONS=detect_leaks=0 real/driver-vuln mk real/image-base.ext4 \
    > real/evidence/real-mkfs.out 2>&1 && has real/evidence/real-mkfs.out 'MKFS_RC=0' \
    && ok "unmodified ext4_mkfs base image" || bad "unmodified ext4_mkfs base image"
python3 real/craft_image.py real/image-base.ext4 real/image-attack.ext4 32777 \
    > real/evidence/craft-71473.out 2>&1 \
    && ok "CVE-2025-71473 image ipg=32777" || bad "CVE-2025-71473 image ipg=32777"
python3 real/craft_image.py real/image-base.ext4 real/image-safe.ext4 8192 \
    >> real/evidence/craft-71473.out 2>&1 \
    && ok "safe image ipg=8192" || bad "safe image ipg=8192"
python3 real/craft_image_71474.py real/image-base.ext4 real/image-71474.ext4 \
    > real/evidence/craft-71474.out 2>&1 \
    && ok "CVE-2025-71474 image gdt=65535" || bad "CVE-2025-71474 image gdt=65535"
sha256sum real/image-base.ext4 real/image-attack.ext4 real/image-safe.ext4 \
    real/image-71474.ext4 > real/evidence/image-hashes.txt

echo "== real mount controls =="
run() { # binary image logfile
    ASAN_OPTIONS=detect_leaks=0 "real/$1" mount "real/$2" > "real/evidence/$3" 2>&1
    return $?
}
set +e
run driver-vuln image-attack.ext4 real-vuln-attack-asan.out
A=$?
run driver-fixed image-attack.ext4 real-fixed-attack-asan.out
B=$?
run driver-vuln image-safe.ext4 real-vuln-safe-asan.out
C=$?
run driver-fixed image-safe.ext4 real-fixed-safe-asan.out
D=$?
run driver-vuln image-71474.ext4 real-vuln-71474-asan.out
E=$?
run driver-fixed image-71474.ext4 real-fixed-71474-asan.out
F=$?
set -e

L=real/evidence
# 71473: real vulnerable write past the real bcache buffer
[ "$A" -ne 0 ] && has $L/real-vuln-attack-asan.out 'AddressSanitizer: heap-buffer-overflow' \
    && has $L/real-vuln-attack-asan.out 'WRITE of size 4098' \
    && has $L/real-vuln-attack-asan.out '0 bytes after 4096-byte region' \
    && has $L/real-vuln-attack-asan.out 'ext4_fs_init_inode_bitmap' \
    && has $L/real-vuln-attack-asan.out 'ext4_fs_get_block_group_ref' \
    && has $L/real-vuln-attack-asan.out 'ext4_buf_alloc' \
    && ok 'vuln ipg=32777 ASan WRITE 4098 at real mount' \
    || bad 'vuln ipg=32777 ASan WRITE 4098 at real mount'
# fixed geometry check rejects the same image at ext4_fs_init()
[ "$B" -eq 95 ] && has $L/real-fixed-attack-asan.out 'FS_INIT_RC=95' \
    && ! has $L/real-fixed-attack-asan.out 'AddressSanitizer' \
    && ok 'fixed rejects ipg=32777 at mount (ENOTSUP=95)' \
    || bad 'fixed rejects ipg=32777 at mount (ENOTSUP=95)'
# safe image with the same UNINIT group flag
[ "$C" -eq 0 ] && has $L/real-vuln-safe-asan.out 'BG_REF_RC=0' \
    && ! has $L/real-vuln-safe-asan.out 'AddressSanitizer' \
    && ok 'vuln safe ipg=8192 clean' || bad 'vuln safe ipg=8192 clean'
[ "$D" -eq 0 ] && has $L/real-fixed-safe-asan.out 'BG_REF_RC=0' \
    && ! has $L/real-fixed-safe-asan.out 'AddressSanitizer' \
    && ok 'fixed safe ipg=8192 clean' || bad 'fixed safe ipg=8192 clean'
# 71474: real block-bitmap OOB bit set
[ "$E" -ne 0 ] && has $L/real-vuln-71474-asan.out 'AddressSanitizer: heap-buffer-overflow' \
    && has $L/real-vuln-71474-asan.out 'READ of size 1' \
    && has $L/real-vuln-71474-asan.out '0 bytes after 4096-byte region' \
    && has $L/real-vuln-71474-asan.out 'ext4_fs_init_block_bitmap' \
    && has $L/real-vuln-71474-asan.out 'ext4_bmap_bit_set' \
    && ok 'vuln gdt=65535 ASan OOB bit set at real mount' \
    || bad 'vuln gdt=65535 ASan OOB bit set at real mount'
[ "$F" -eq 95 ] && has $L/real-fixed-71474-asan.out 'FS_INIT_RC=95' \
    && ! has $L/real-fixed-71474-asan.out 'AddressSanitizer' \
    && ok 'fixed rejects gdt=65535 at mount (ENOTSUP=95)' \
    || bad 'fixed rejects gdt=65535 at mount (ENOTSUP=95)'

echo "REAL_PASS=$pass REAL_FAIL=$fail"
[ "$fail" -eq 0 ] && echo 'REAL MOUNT REPLAY PASS' || echo 'REAL MOUNT REPLAY FAIL'
exit "$fail"
