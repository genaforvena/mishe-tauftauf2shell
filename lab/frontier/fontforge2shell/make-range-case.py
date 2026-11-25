#!/usr/bin/env python3
"""W26: prove getformint16() does not sign-extend complete glyph indices."""
import hashlib
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = bytearray((HERE / "truncated.pcf").read_bytes())


def case(name, full):
    data = bytearray(BASE[:0x124])
    struct.pack_into("<HHHH", data, 0x118, 0x4142, 0x4142, 0x0043, 0x0043)
    if full:
        struct.pack_into("<H", data, 0x122, 0xBEF2)
    else:
        data[0x122] = 0xF2
        data = data[:0x123]
    (HERE / name).write_bytes(data)
    print(f"{name}: {len(data)} bytes sha256={hashlib.sha256(data).hexdigest()}")


case("range-full.pcf", True)
case("range-partial.pcf", False)
for name in ("range-full", "range-partial"):
    (HERE / f"{name}.ff").write_text(
        "New()\n" f'Import("{HERE / (name + ".pcf")}")\n'
    )
