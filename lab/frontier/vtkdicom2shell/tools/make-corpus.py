#!/usr/bin/env python3
"""Generate a broad crafted DICOM sequence-item corpus to hunt for a parser
path that yields an invalid vtkDICOMValue (delete precondition for the
vtkDICOMItem count/store desync). Local lab use only.
"""
import os
import struct
import sys

OUTDIR = sys.argv[1] if len(sys.argv) > 1 else "evidence/corpus"

VRS = ["AE", "AS", "AT", "CS", "DA", "DS", "DT", "FD", "FL", "IS", "LO",
       "LT", "OB", "OD", "OF", "OL", "OW", "PN", "SH", "SL", "SQ", "SS",
       "ST", "TM", "UC", "UI", "UL", "UN", "UR", "US", "UT", "OV", "SV",
       "UV", "OX", "XS", "ZZ", "XX"]
LONG_VRS = {"OB", "OD", "OF", "OL", "OV", "OW", "SQ", "UC", "UN",
            "UR", "UT", "SV", "UV"}


def preamble():
    return b"\x00" * 128 + b"DICM"


def meta_header(tsyntax):
    ts = tsyntax.encode() + b"\x00"
    tail = b"\x02\x00\x10\x00UI" + struct.pack("<H", len(ts)) + ts
    glen = 12 + len(tail) - 12
    return (b"\x02\x00\x00\x00UL" + struct.pack("<H", 4) +
            struct.pack("<I", glen) + tail)


def ex(group, element, vr, value):
    head = struct.pack("<HH", group, element) + vr.encode("ascii")
    if vr in LONG_VRS:
        return head + b"\x00\x00" + struct.pack("<I", len(value)) + value
    return head + struct.pack("<H", len(value)) + value


def imp(group, element, value):
    return struct.pack("<HH", group, element) + struct.pack("<I", len(value)) + value


def item(payload):
    return struct.pack("<HHI", 0xFFFE, 0xE000, len(payload)) + payload


def seq_ex(payload):
    return ex(0x0008, 0x1110, "SQ", item(payload) + struct.pack("<HHI", 0xFFFE, 0xE0DD, 0))


def seq_im(payload):
    return imp(0x0008, 0x1110, item(payload) + struct.pack("<HHI", 0xFFFE, 0xE0DD, 0))


def us(g, e, v):
    return ex(g, e, "US", struct.pack("<H", v))


def write(name, data):
    with open(os.path.join(OUTDIR, name), "wb") as f:
        f.write(data)


def main():
    os.makedirs(OUTDIR, exist_ok=True)
    fill = b"".join(us(0x0008, i, 0x100 + i) for i in range(1, 5))
    tail = b"".join(us(0x0009, i, 0x200 + i) for i in range(5, 9))
    n = 0

    # A: explicit VR LE candidate at interior slot with many VRs / lengths.
    for vr in VRS:
        for j, payload in enumerate((b"", b"\x00\x00", b"\x00\x00\x00\x00")):
            cand = ex(0x0009, 0x0003, vr, payload)
            write("a-exp-%s-%d.dcm" % (vr, j),
                  preamble() + seq_ex(fill[:20] + cand + fill[20:] + tail))
            n += 1

    # B: undefined-length (0xffffffff) candidate VR, explicit LE.
    for vr in VRS:
        cand = struct.pack("<HH", 0x0009, 0x0003) + vr.encode("ascii") + b"\x00\x00" + b"\xff\xff\xff\xff"
        body = fill[:20] + cand + struct.pack("<HHI", 0xFFFE, 0xE0DD, 0) + fill[20:] + tail
        write("b-undef-%s.dcm" % vr, preamble() + seq_ex(body))
        n += 1

    # C: implicit VR LE (transfer syntax in meta), zero-length candidates.
    for g, e in [(0x0009, 0x0003), (0x0008, 0x0003), (0x0009, 0x0010),
                 (0x0009, 0x0001), (0x0008, 0x1110)]:
        cand = imp(g, e, b"")
        body = b"".join(imp(0x0008, i, struct.pack("<H", 0x100 + i)) for i in range(1, 5))
        body += cand + b"".join(imp(0x0009, i, struct.pack("<H", 0x200 + i)) for i in range(5, 9))
        write("c-impl-%04x-%04x.dcm" % (g, e),
              preamble() + meta_header("1.2.840.10008.1.2") + seq_im(body))
        n += 1

    # D: explicit private-creator tag (0009,0010) with several VRs.
    for vr in ("LO", "UN", "US", "ZZ", "SQ"):
        cand = ex(0x0009, 0x0010, vr, b"")
        write("d-privcr-%s.dcm" % vr,
              preamble() + seq_ex(fill[:20] + cand + fill[20:] + tail))
        n += 1

    # E: defined-length zero-length SQ at interior slot.
    cand = ex(0x0009, 0x0003, "SQ", b"")
    write("e-zero-sq.dcm", preamble() + seq_ex(fill[:20] + cand + fill[20:] + tail))
    n += 1

    print("generated %d files in %s" % (n, OUTDIR))


if __name__ == "__main__":
    main()
