#!/usr/bin/env python3
"""Check whether a real-consumer overwrite covers a pointer-valued qword."""
import re
import sys
from pathlib import Path

text = Path(sys.argv[1]).read_text()
match = re.search(r"BEFORE_BUF=(0x[0-9a-f]+) LSIZE=-1", text)
if not match or "AFTER_BUF=" not in text:
    sys.exit(1)
buf = int(match.group(1), 16)
before, after = text.split("AFTER_BUF", 1)


def qwords(section):
    values = {}
    for line in section.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].startswith("0x"):
            try:
                address = int(parts[0].rstrip(":"), 16)
            except ValueError:
                continue
            for index, token in enumerate(parts[1:]):
                try:
                    values[address + index * 8] = int(token, 16)
                except ValueError:
                    break
    return values


old_values = qwords(before)
new_values = qwords(after)
hits = []
for offset in range(0, 64, 8):
    old = old_values.get(buf + offset)
    new = new_values.get(buf + offset)
    if old is None:
        continue
    canonical = (0x550000000000 <= old < 0x560000000000
                 or 0x7F0000000000 <= old < 0x800000000000)
    if canonical and new == 0x4141414141414141:
        hits.append((offset, old))
for offset, old in hits:
    print(f"pointer_offset={offset:#x} before={old:#x} after=0x4141414141414141")
sys.exit(0 if hits else 1)
