#!/usr/bin/env python3
"""List writable globals of at least 32 bytes from `nm --size-sort` output."""

import sys

for line in sys.stdin:
    fields = line.split()
    if len(fields) < 3:
        continue
    size, kind, name = fields[:3]
    if kind not in ("b", "B", "d", "D"):
        continue
    try:
        nbytes = int(size, 16)
    except ValueError:
        continue
    if nbytes >= 32:
        print(f"{nbytes:8d} {kind} {name}")
