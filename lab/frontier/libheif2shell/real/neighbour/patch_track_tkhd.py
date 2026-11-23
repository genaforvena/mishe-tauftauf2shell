#!/usr/bin/env python3
"""Patch the first 'tkhd' box's declared width/height (16.16 fixed point).

W178: an uncompressed-coded sequence can carry a 64x65 frame 1, but the
encoder writes the last frame's size into tkhd. The x265 re-encode driver reads
tkhd to size its fixed encoder, so restore the first frame's 512x64 here. The
decoded sample dimensions are carried per sample and are not touched.

Usage: patch_track_tkhd.py INPUT OUTPUT [WIDTH HEIGHT]   (default 512 64)
"""
import hashlib
import struct
import sys


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    src, dst = sys.argv[1], sys.argv[2]
    width = int(sys.argv[3]) if len(sys.argv) > 3 else 512
    height = int(sys.argv[4]) if len(sys.argv) > 4 else 64
    data = bytearray(open(src, "rb").read())
    at = data.find(b"tkhd")
    if at < 4:
        sys.exit("no tkhd box")
    box = at - 4
    size, = struct.unpack_from(">I", data, box)
    version = data[box + 8]
    if size != 92 or version != 0:
        sys.exit(f"unexpected tkhd size/version: {size} {version}")
    off = box + 84
    old_w, old_h = struct.unpack_from(">II", data, off)
    struct.pack_into(">II", data, off, width << 16, height << 16)
    open(dst, "wb").write(data)
    print(f"tkhd at byte {box}: {old_w >> 16}x{old_h >> 16} -> {width}x{height}")
    print(f"sha256 {hashlib.sha256(bytes(data)).hexdigest()}")


if __name__ == "__main__":
    main()
