#!/usr/bin/env python3
"""Print the negative glyph index that writes Encoding.tounicode in a W27
gdb transcript. The Encoding/encs distance shifts with argv/env length, so
the target must be derived from the same gdb invocation pattern as the write.

Usage: python3 w27-target.py TRANSCRIPT
Exits 2 if no delta line, 3 if the Encoding object is outside the reachable
window or its tounicode slot is not 4-byte aligned in that window.
"""
import pathlib
import re
import sys

text = pathlib.Path(sys.argv[1]).read_text(errors="replace")
match = re.search(r"delta=-(\d+)", text)
if not match:
    raise SystemExit(2)
distance = int(match.group(1))
if distance <= 72 or distance > 1024 or (distance - 72) % 4:
    raise SystemExit(3)
print(-(distance - 72) // 4)
