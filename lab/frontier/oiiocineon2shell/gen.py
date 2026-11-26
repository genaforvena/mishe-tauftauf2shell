#!/usr/bin/env python3
"""Generate .cin headers: advisory PoC (255), boundary (8), valid (1)."""
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "files"
OUT.mkdir(exist_ok=True)

for name, count in (("attack255.cin", 0xFF), ("safe8.cin", 8), ("valid1.cin", 1)):
    buf = bytearray(2048)
    struct.pack_into(">I", buf, 0, 0x802A5FD7)  # CINEON_MAGIC_COOKIE
    buf[193] = count  # offsetof(numberOfElements)
    (OUT / name).write_bytes(buf)
    print(f"{name}: numberOfElements={count}, {len(buf)} bytes")
