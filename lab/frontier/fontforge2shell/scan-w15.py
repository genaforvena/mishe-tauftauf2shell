#!/usr/bin/env python3
"""W15: scan the negative-w glyph write window for live code pointers.

Usage: python3 scan-w15.py DUMP GDB_OUT BINARY_SUBSTRING

DUMP is a 131072-byte dump of (char*)encs-131072 .. (char*)encs taken at
fvimportbdf.c:1751 with glyph<0. GDB_OUT is the gdb transcript containing
`info proc mappings`; BINARY_SUBSTRING selects that build's executable r-xp
line. Every 8-byte-aligned word in the window whose value lies in that
executable mapping is printed with its bytes, so ASCII string fragments can
be distinguished from real function pointers.
"""
import struct
import sys

dump_path, gdb_path, needle = sys.argv[1:4]
data = open(dump_path, "rb").read()
if len(data) != 131072:
    sys.exit(f"dump length {len(data)} != 131072")

lo = hi = None
for line in open(gdb_path, errors="replace"):
    if needle in line and " r-xp " in line:
        parts = line.split()
        lo, hi = int(parts[0], 16), int(parts[1], 16)
        break
if lo is None:
    sys.exit(f"no r-xp mapping for {needle} in {gdb_path}")

print(f"RANGE {lo:#x}..{hi:#x}")
cands = []
for off in range(0, len(data) - 7, 8):
    value = struct.unpack_from("<Q", data, off)[0]
    if lo <= value < hi:
        raw = data[off:off + 8]
        ascii4 = sum(32 <= b < 127 for b in raw[:4])
        cands.append((off - 131072, value, raw, ascii4))
print(f"CAND_COUNT {len(cands)}")
for rel, value, raw, ascii4 in cands:
    print(f"CAND encs{rel:+d} {value:#010x} bytes={raw.hex()} ascii4={ascii4}")
if not cands:
    print("RESULT NONE")
elif all(ascii4 >= 3 for _, _, _, ascii4 in cands):
    print("RESULT ASCII_ONLY")
else:
    print("RESULT CODE_POINTER_CANDIDATES")
