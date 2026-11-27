#!/usr/bin/env python3
"""Deterministic encoded_oauth_token inputs for the coturn nonce sink."""
from pathlib import Path
import struct

ROOT = Path(__file__).resolve().parent
OUT = ROOT / "inputs"
OUT.mkdir(exist_ok=True)


def token(nonce_len: int, fill: int = 0x41) -> bytes:
    # 2-byte big-endian nonce_len, nonce_len nonce bytes, then 4-byte key_len,
    # 8-byte timestamp, 2-byte lifetime, 16-byte GCM tag, 1 ciphertext byte.
    return struct.pack(">H", nonce_len) + bytes([fill]) * nonce_len + bytes(31)


for name, length in (("nonce-990", 990), ("nonce-256-safe", 256), ("nonce-16-safe", 16)):
    data = token(length)
    assert len(data) == length + 33 and len(data) <= 1024
    (OUT / f"{name}.bin").write_bytes(data)
    print(f"{name}: {len(data)} bytes")
