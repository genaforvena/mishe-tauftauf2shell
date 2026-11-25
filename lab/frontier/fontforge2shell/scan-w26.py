#!/usr/bin/env python3
"""W26: scan the actual negative-glyph window against every executable map.

Usage: python3 scan-w26.py DUMP GDB_OUT
DUMP is the W15-style 128 KiB dump; only its final 1024 bytes are reachable.
getformint16() does not sign-extend: a complete two-byte index is 0..65535,
while EOF yields -1 or low_byte-256. Thus only glyph -256..-1 is accepted.
Unlike scan-w15.py, this includes shared-library and vDSO code mappings.
Candidates remain hypotheses until tied to a live object and observed call.
"""
import pathlib
import struct
import sys

if len(sys.argv) != 3:
    raise SystemExit("usage: scan-w26.py DUMP GDB_OUT")
data = pathlib.Path(sys.argv[1]).read_bytes()
if len(data) != 131072:
    raise SystemExit(f"dump length {len(data)} != 131072")
ranges = []
for line in pathlib.Path(sys.argv[2]).read_text(errors="replace").splitlines():
    fields = line.split()
    if len(fields) >= 5 and fields[4] == "r-xp":
        lo, hi = int(fields[0], 16), int(fields[1], 16)
        label = fields[5] if len(fields) > 5 else "[anonymous]"
        ranges.append((lo, hi, label))
if not ranges:
    raise SystemExit("no r-xp mappings")
for lo, hi, label in ranges:
    print(f"RANGE {lo:#x}..{hi:#x} {label}")
print("WINDOW encs-1024..encs")
cands = []
for off in range(len(data) - 1024, len(data) - 7, 8):
    value = struct.unpack_from("<Q", data, off)[0]
    for lo, hi, label in ranges:
        if lo <= value < hi:
            raw = data[off:off + 8]
            ascii4 = sum(32 <= b < 127 for b in raw[:4])
            cands.append((off - 131072, value, raw, ascii4, label))
            break
print(f"CAND_COUNT {len(cands)}")
for rel, value, raw, ascii4, label in cands:
    print(f"CAND encs{rel:+d} {value:#010x} bytes={raw.hex()} ascii4={ascii4} map={label}")
if not cands:
    print("RESULT NONE")
elif all(ascii4 >= 3 for _, _, _, ascii4, _ in cands):
    print("RESULT ASCII_ONLY")
else:
    print("RESULT CODE_POINTER_CANDIDATES")
