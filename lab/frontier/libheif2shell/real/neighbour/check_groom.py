#!/usr/bin/env python3
"""Assert the W169 grooming negative from a saved gdb_groom.cmd log.

The prediction tested: if the replacement plane reuses the groomed chunk A,
the one OOB row would reach the live Victim B (fn pointer at B+0). Observed:
the plane came from a different heap region, B stayed intact, and the process
still aborted on top-chunk metadata. This is a rung-4 mechanics negative, not
file-derived placement and not rung 5.

Usage: check_groom.py evidence/groom-gdb.out
"""
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()

groom = re.search(r"GROOM A=0x([0-9a-f]+) B=0x([0-9a-f]+)", text)
plane = re.search(r"PLANE2=0x([0-9a-f]+) A=0x([0-9a-f]+) B=0x([0-9a-f]+)", text)
final = re.search(r"B fn=0x([0-9a-f]+) tag0=0x([0-9a-f]{2}) tag8=0x([0-9a-f]{2})", text)
assert groom and plane and final, "missing grooming/plane/final observations"

a = int(groom.group(1), 16)
b = int(groom.group(2), 16)
p2 = int(plane.group(1), 16)
assert b - a == 0x8020, f"groomed chunks not adjacent: A={a:#x} B={b:#x}"
assert p2 != a, "plane unexpectedly reused groomed chunk A"
fn = int(final.group(1), 16)
assert fn != 0 and final.group(2) == "a5" and final.group(3) == "ad", \
    "victim B was overwritten"
assert "malloc(): corrupted top size" in text, "expected allocator abort"
assert "SIGABRT" in text, "expected abort signal"

print("PASS: groomed live victim not adjacent to plane; B intact; plane elsewhere; abort on top metadata")
print(f"      A={a:#x} B={b:#x} (B-A={b-a:#x}) plane2={p2:#x} fn={fn:#x}")
