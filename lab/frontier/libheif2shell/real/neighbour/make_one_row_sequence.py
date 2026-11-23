#!/usr/bin/env python3
"""Derive a one-row-overflow MJPEG sequence from W162's committed patterned input.

Only the second sample's SOF0 height changes (512 -> 65); its width stays 64.
The decoder then returns frame 1 as 64x65 while the x265 encoder still pads to
the first frame's 512x64, so exactly one decoded row (row 64) is copied at the
512-byte stride past the 32783-byte replacement plane. Entropy bytes and every
other container byte are unchanged.

Usage: make_one_row_sequence.py [OUTPUT.heif]
Default output: /tmp/libheif-one-row.heif
"""
import hashlib
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from make_pattern_sequence import patch_second_sof  # noqa: E402

SOURCE = HERE / "pattern-mixed.heif"
SOURCE_SHA256 = "8f09b93c85341e9e120e75304379a79df11518cb7def4cc2fc6cdee7da151c1c"
OUTPUT_SHA256 = "e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67"


def main() -> None:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/tmp/libheif-one-row.heif")
    data = SOURCE.read_bytes()
    if hashlib.sha256(data).hexdigest() != SOURCE_SHA256:
        raise SystemExit("source pattern-mixed.heif hash mismatch")
    patch_second_sof(SOURCE, out, 65, 64)
    digest = hashlib.sha256(out.read_bytes()).hexdigest()
    if digest != OUTPUT_SHA256:
        raise SystemExit(f"unexpected output hash {digest}")
    print(f"wrote {out}: {out.stat().st_size} bytes, sha256={digest}")


if __name__ == "__main__":
    main()
