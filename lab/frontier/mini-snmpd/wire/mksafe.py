#!/usr/bin/env python3
"""Craft an in-bounds SNMPv1 GET datagram (safe wire control)."""
import struct
import sys


def tlv(tag, value):
    n = len(value)
    if n < 0x80:
        return bytes([tag, n]) + value
    return bytes([tag, 0x82]) + struct.pack(">H", n) + value



version = tlv(0x02, b"\x00")
community = tlv(0x04, b"public")
oid = tlv(0x06, b"\x2b\x06\x01")
varbind = tlv(0x30, oid + tlv(0x05, b""))
varbinds = tlv(0x30, varbind)
request_body = (tlv(0x02, b"\x01") + tlv(0x02, b"\x00") +
                tlv(0x02, b"\x00") + varbinds)
message = tlv(0x30, version + community + tlv(0xA0, request_body))

with open(sys.argv[1] if len(sys.argv) > 1 else "safe.bin", "wb") as f:
    f.write(message)
print(f"SAFE_BYTES={len(message)} oid_len=3")
