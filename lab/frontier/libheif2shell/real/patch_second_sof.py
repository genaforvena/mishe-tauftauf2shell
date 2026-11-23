#!/usr/bin/env python3
"""Derive the mixed-size MJPEG sequence from the upstream-generated reference.

`reference-same-size.heif` was produced by the pinned v1.23.6 `heif-enc -S
--jpeg jf_1.jpg jf_2.jpg` from two 512x64 JPEGs. Its last `mdat` holds two
1138-byte JPEG samples. Patch only the second sample's SOF0 height and width
(64,512 -> 512,64); the decoder then allocates a 64x512 image for frame 1,
while the x265 encoder still pads to the first frame's 512x64.

Usage: patch_second_sof.py REFERENCE.heif OUTPUT.heif
"""
import struct
import sys
from pathlib import Path

SAMPLE_SIZE = 1138


def main() -> None:
    ref, out = map(Path, sys.argv[1:3])
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
    if not mdats:
        raise SystemExit("no mdat box")
    mdat_start, mdat_size = mdats[-1]
    payload = mdat_start + 8
    if mdat_size - 8 != 2 * SAMPLE_SIZE:
        raise SystemExit(f"unexpected mdat payload size {mdat_size - 8}")

    second = payload + SAMPLE_SIZE
    sof = data.find(b"\xff\xc0", second, payload + 2 * SAMPLE_SIZE)
    if sof < 0:
        raise SystemExit("no SOF0 marker in second sample")
    height, width = struct.unpack_from(">HH", data, sof + 5)
    if (width, height) != (512, 64):
        raise SystemExit(f"unexpected second-frame size {width}x{height}")
    struct.pack_into(">HH", data, sof + 5, 512, 64)  # SOF order is height,width

    out.write_bytes(data)
    print(f"wrote {out}: {len(data)} bytes, SOF0 at {sof}, frame 1 64x512")


if __name__ == "__main__":
    main()
