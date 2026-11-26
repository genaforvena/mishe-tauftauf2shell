#!/usr/bin/env python3
"""Summarize gdb readbacks of CVE-2025-71474 bit-set writes into live ext4_buf.bc.

Each section of the input is delimited by '=== GDT=<value> ===' and contains
BC_BEFORE/BC_AFTER lines printed by run-gdt-bit.sh at src/ext4_fs.c:332 and
:335. EXPECT maps the superblock field to the mask that ext4_fs_init_block_bitmap
must OR into the low byte of bc: bit_max = 2 + s_reserved_gdt_blocks, and bit
index 8*4152 begins that pointer byte. gdt=8 is the in-bounds control.
"""
import re
import sys

EXPECT = {
    8: 0x00,
    33215: 0x01,
    33216: 0x03,
    33217: 0x07,
    33218: 0x0f,
    33220: 0x3f,
    33222: 0xff,
}

text = open(sys.argv[1], encoding="utf-8").read()
sections = re.split(r"^=== GDT=(\d+) ===$", text, flags=re.M)
matched = 0
for i in range(1, len(sections) - 1, 2):
    gdt = int(sections[i])
    body = sections[i + 1]
    before = re.search(r"^BC_BEFORE=(0x[0-9a-f]+) DELTA=(-?\d+)$", body, re.M)
    after = re.search(r"^BC_AFTER=(0x[0-9a-f]+) BITBYTE=(0x[0-9a-f]+)$", body, re.M)
    mask = EXPECT.get(gdt)
    if not (before and after) or mask is None:
        print(f"GDT_BITS gdt={gdt} MATCH=0 reason=missing-readback-or-expectation")
        continue
    b, a = int(before.group(1), 16), int(after.group(1), 16)
    delta = int(before.group(2))
    good = (delta == 4112 and b != 0 and mask is not None
            and (a & 0xff) == ((b | mask) & 0xff)
            and (a & ~0xff) == (b & ~0xff))
    matched += int(good)
    print(f"GDT_BITS gdt={gdt} before={before.group(1)} after={after.group(1)} "
          f"delta={delta} mask=0x{mask:02x} MATCH={int(good)}")
print(f"GDT_MATCHED={matched}")
