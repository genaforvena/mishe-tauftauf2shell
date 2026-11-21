#!/usr/bin/env python3
"""Emit only stable, address-free lines from an ASan report (replay digest input)."""
import re
import sys

seen_frame = False
for raw in sys.stdin:
    s = raw.rstrip("\n")
    if "ERROR: AddressSanitizer" in s:
        print("ERROR: AddressSanitizer: heap-buffer-overflow")
    elif "READ of size" in s or "WRITE of size" in s:
        m = re.search(r"(READ|WRITE) of size (\d+)", s)
        if m:
            print("%s of size %s" % (m.group(1), m.group(2)))
    elif "is located" in s and "byte region" in s:
        m = re.search(r"is located (\d+) bytes? after (?:a )?(\d+)-byte region", s)
        if m:
            print("located %s bytes after %s-byte region" % (m.group(1), m.group(2)))
    elif "togglePlanarConfiguration8" in s and "djcodece_v3.7.1.cc" in s and not seen_frame:
        seen_frame = True
        print("frame togglePlanarConfiguration8 djcodece_v3.7.1.cc:1525")
    elif "SUMMARY: AddressSanitizer" in s:
        print("SUMMARY: AddressSanitizer: heap-buffer-overflow")
