#!/usr/bin/env python3
"""Normalize ASan/harness output into replay-stable text for hash comparison."""
import re
import sys

raw = open(sys.argv[1], encoding="utf-8", errors="replace").read()
lines = []
for ln in raw.splitlines():
    s = ln
    # Drop allocator-layout-dependent shadow-byte rows.
    if re.match(r"^\s*(=>)?0x[0-9a-f]+:", s):
        continue
    if s.startswith("Shadow bytes around") or s.startswith("Shadow byte legend"):
        continue
    if "Addressable:" in s or "redzone:" in s or "Poisoned by user:" in s:
        continue
    if "Partially addressable:" in s:
        continue
    s = re.sub(r"==\d+==", "==PID==", s)
    s = re.sub(r"0x[0-9a-fA-F]+", "0xADDR", s)
    s = re.sub(r"BuildId: [0-9a-fA-F]+", "BuildId: ID", s)
    s = re.sub(r"(/[\w.\-+]+){2,}", "PATH", s)
    s = re.sub(r"\s+", " ", s).strip()
    if s:
        lines.append(s)
print("\n".join(lines))
