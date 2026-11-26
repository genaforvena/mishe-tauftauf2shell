#!/usr/bin/env python3
"""Build the advisory-shaped .imatrix inputs. Layout: int32 n_entries, then
per entry int32 len, len name bytes, int32 ncall, int32 nval, nval float32."""
import os
import struct
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "evidence")
os.makedirs(OUT, exist_ok=True)


def entry(name, ncall, nval, base=1.0):
    b = name.encode()
    vals = [base + i for i in range(nval)]
    return struct.pack("<i", len(b)) + b + struct.pack("<ii", ncall, nval) + struct.pack("<%df" % nval, *vals)


def write(name, entries):
    path = os.path.join(OUT, name)
    with open(path, "wb") as f:
        f.write(struct.pack("<i", len(entries)))
        for e in entries:
            f.write(e)
    print(path, os.path.getsize(path))


nval = int(sys.argv[1]) if len(sys.argv) > 1 else 64
# Two entries with the SAME tensor name: the second nval drives the loop while
# the vectors stay sized to the first nval.
write("attack.imatrix", [entry("blk.0", 1, 1), entry("blk.0", 1, nval)])
# Distinct names: each entry resizes its own vectors; no overflow.
write("safe.imatrix", [entry("blk.0", 1, 1), entry("blk.1", 1, nval)])
