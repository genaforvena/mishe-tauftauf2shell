#!/usr/bin/env python3
"""Check the W170 plain-allocator OOB-source invariants on three 4096-byte dumps.

Usage: analyze_oob_source.py RUN1 RUN2 PIXEL5A
RUN1 and RUN2 are repeats of cases/poc.exr (pixel 0x41); PIXEL5A is the
same forge with pixel 0x5a. The in-bounds 64 bytes must track the file byte;
the 4032 out-of-bounds bytes must differ only inside one short window, and
that window must also vary on a same-input repeat (i.e. not file-controlled).
"""
import sys
from pathlib import Path

blobs = [Path(p).read_bytes() for p in sys.argv[1:4]]
if any(len(b) != 4096 for b in blobs):
    print("FAIL: expected three 4096-byte dumps")
    sys.exit(1)
r1, r2, p5a = blobs
ok = True


def check(name, condition, detail=""):
    global ok
    print(("PASS " if condition else "FAIL ") + name + (" " + detail if detail else ""))
    ok = ok and condition


def oob_diffs(a, b):
    return [i for i in range(64, 4096) if a[i] != b[i]]


def window(ds):
    return (min(ds), max(ds)) if ds else None


check("inbounds-r1-0x41", r1[:64] == bytes([0x41]) * 64)
check("inbounds-p5a-0x5a", p5a[:64] == bytes([0x5a]) * 64)
d_repeat = oob_diffs(r1, r2)
d_pixel = oob_diffs(r1, p5a)
w_repeat, w_pixel = window(d_repeat), window(d_pixel)
check("repeat-oob-diff-window", bool(d_repeat) and len(d_repeat) <= 16,
      f"n={len(d_repeat)} window={w_repeat}")
check("pixel-oob-diff-window", bool(d_pixel) and len(d_pixel) <= 16,
      f"n={len(d_pixel)} window={w_pixel}")
check("same-oob-diff-window", w_repeat == w_pixel,
      f"repeat={w_repeat} pixel={w_pixel}")
check("oob-not-file-chosen", d_pixel == d_repeat and d_repeat != [] and
      all(r1[i] != p5a[i] for i in d_pixel) and
      all(r1[i] != r2[i] for i in d_repeat))
print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
