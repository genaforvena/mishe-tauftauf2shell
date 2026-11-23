#!/usr/bin/env python3
"""Assert the W172 wire-input + live-victim clean-return observations.

Usage: check_wire_interpose.py EVIDENCE_DIR

Checks two saved runs of reencode_wire_interpose.cc on pinned plain Release
v1.23.6: a controlled 64x65 frame-1 JPEG and a patterned one-row variant. In
both, the mixed-size frame arrives as bytes on 127.0.0.1, the padding plane
reuses an adjacent live Victim, and the harness retains frame 1 so the process
exits cleanly with the overwritten bytes intact.

Rung 4 mechanics only: the victim is harness-placed, the 8 bytes are uniform
file-derived values, not a valid address; retention is a harness lifetime
choice. No marker execution, no command, no real network service, no rung 5.
"""
import re
import sys
from pathlib import Path

here = Path(sys.argv[1])
runs = [
    ("wire-interpose-retain.out", 6004, "40" * 8, "40", "500000500021e"),
    ("wire-interpose-pattern-retain.out", 5004, "a8" * 8, "b6", "9c" * 8),
]

for name, size, fn_hex, tag_byte, header in runs:
    text = (here / name).read_text()
    assert f"WIRE_RECEIVED {size} bytes" in text, f"{name}: wire bytes missing"
    groom = re.search(r"GROOM count=\d+ A=0x([0-9a-f]+) B=0x([0-9a-f]+) delta=(\d+)", text)
    assert groom, f"{name}: no GROOM line"
    a, b, delta = int(groom.group(1), 16), int(groom.group(2), 16), int(groom.group(3))
    assert b - a == delta == 0x8020, f"{name}: victim not adjacent"
    assert re.search(r"CALLOC32783 count=2 ret=0x[0-9a-f]+ == A", text), \
        f"{name}: plane did not reuse A"
    assert "WIRE_FRAME 1 decoded 64x65 stride=64" in text
    assert "WIRE_ENCODE_RC 0" in text
    assert f"VICTIM fn=0x{fn_hex}" in text, f"{name}: fn bytes mismatch"
    assert f"tag[0..7]={tag_byte} " * 8 in text or \
        "tag[0..7]=" + " ".join([tag_byte] * 8) in text, f"{name}: tag mismatch"
    assert f"B-8=0x{header}" in text, f"{name}: chunk header mismatch"
    assert f"POST fn=0x{fn_hex}" in text, f"{name}: POST state missing"
    assert "CLIENT driver_rc=0" in text, f"{name}: clean return failed"
    print(f"PASS {name}: wire {size}B -> adjacent A+B -> fn=0x{fn_hex}, rc 0")

print("PASS: wire-derived bytes overwrite a live object with a clean return (rung 4, not rung 5)")
