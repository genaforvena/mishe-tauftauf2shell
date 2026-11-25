#!/usr/bin/env python3
"""W18: assert a prior complete-table import moved `encs` in both builds.

Reads the W15 single-import baseline and the W18 two-import transcripts and
prints the exact pointer delta. Exits nonzero unless both builds used a
different `encs` address and the W18 store is the same glyph=-1, i=3 case.
"""
import re
import sys


def encs(path, tag):
    for line in open(path, errors="replace"):
        m = re.search(tag + r" encs=(0x[0-9a-f]+) glyph=(-?\d+) i=(\d+)", line)
        if m:
            return int(m.group(1), 16), int(m.group(2)), int(m.group(3))
    sys.exit(f"no {tag} breakpoint line in {path}")


ok = True
for mode in ("pie", "nopie"):
    base = encs(f"gdb-w15-{mode}.out", "W15")
    cur = encs(f"gdb-w18-{mode}.out", "W18")
    print(
        f"ALLOC_STATE {mode} W15={base[0]:#x} W18={cur[0]:#x} "
        f"delta={cur[0] - base[0]:+#x} glyph={cur[1]} i={cur[2]}"
    )
    ok &= base != cur and cur[1] == -1 and cur[2] == 3
print(f"ALLOC_STATE_OK {'yes' if ok else 'no'}")
sys.exit(0 if ok else 1)
