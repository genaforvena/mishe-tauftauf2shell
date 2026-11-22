#!/usr/bin/env python3
"""Normalize h2o2shell harness output into replay-stable evidence lines.

Strips PIDs, addresses and absolute build paths; keeps the observed bytes,
line numbers, sizes and verdicts.  One sha256 per variant is emitted.
"""
import hashlib
import re
import sys
from pathlib import Path

OUT = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
variants = ["vuln-asan", "fixed-asan", "vuln-plain", "fixed-plain",
            "vuln-safe", "fixed-safe"]

for v in variants:
    txt = (OUT / f"out-{v}.txt").read_text(errors="replace")
    rc = (OUT / f"out-{v}.rc").read_text().strip()
    lines = []
    for raw in txt.splitlines():
        line = raw.strip()
        if "ERROR: AddressSanitizer:" in line or line.startswith("WRITE of size"):
            line = re.sub(r"==\d+==", "==PID==", line)
            line = re.sub(r"0x[0-9a-f]+", "0xADDR", line)
            lines.append(line)
        elif re.match(r"#[01] ", line):
            line = re.sub(r"0x[0-9a-f]+", "0xADDR", line)
            line = re.sub(r"\S*/lib/core/logconf\.c", "lib/core/logconf.c", line)
            line = re.sub(r"\S*/harness/logconf_harness\.c", "harness/logconf_harness.c", line)
            line = re.sub(r"\S*/(lc-(?:vuln|fixed)-(?:asan|plain|safe))", r"\1", line)
            lines.append(line)
        elif "is located 0 bytes after" in line:
            lines.append(re.sub(r"0x[0-9a-f]+", "0xADDR", line))
        elif line.startswith("SUMMARY: AddressSanitizer:"):
            line = re.sub(r"\S*/lib/core/logconf\.c", "lib/core/logconf.c", line)
            lines.append(line)
        elif line.startswith(("OUT_LEN=", "OUT=", "TAIL=", "EXPECT_TAIL=")):
            if line.startswith("TAIL=") or line.startswith("EXPECT_TAIL="):
                key, _, val = line.partition("=")
                line = f"{key}={val[:40]}"
            lines.append(line)
    digest = hashlib.sha256(("\n".join(lines) + f"\nRC={rc}\n").encode()).hexdigest()
    print(f"{v:12s} sha256={digest} rc={rc} lines={len(lines)}")
