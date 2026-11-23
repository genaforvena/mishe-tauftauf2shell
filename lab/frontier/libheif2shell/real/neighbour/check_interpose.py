#!/usr/bin/env python3
"""Assert the W171 live-victim adjacency and clean-return observations.

Usage: check_interpose.py EVIDENCE_DIR

Checks three saved runs of the calloc-interposed driver on pinned plain
Release v1.23.6:
  * controlled release: adjacent victim overwritten, allocator abort at release;
  * controlled retain: same overwrite, process exits cleanly (rc 0);
  * patterned one-row retain: pointer bytes track the file, rc 0.

This is rung-4 mechanics: harness-placed victim, file-derived uniform bytes,
no valid pointer target, no marker, no wire input, no rung 5.
"""
import re
import sys
from pathlib import Path

here = Path(sys.argv[1])
controlled_release = (here / "interpose-controlled-release.out").read_text()
controlled_retain = (here / "interpose-controlled-retain.out").read_text()
pattern_retain = (here / "interpose-pattern-retain.out").read_text()
rcs = (here / "interpose-rc.txt").read_text()


def inspect(text, fn_hex, tag_hex, header_hex):
    groom = re.search(r"GROOM count=\d+ A=0x([0-9a-f]+) B=0x([0-9a-f]+) delta=(\d+)", text)
    assert groom, "missing GROOM line"
    a, b, delta = int(groom.group(1), 16), int(groom.group(2), 16), int(groom.group(3))
    assert b - a == delta == 0x8020, f"victim not adjacent: {a:#x} {b:#x} {delta}"
    assert re.search(r"CALLOC32783 count=2 ret=0x[0-9a-f]+ == A", text), \
        "padding reallocation did not reuse A"
    assert re.search(r"CALLOC32783 count=1 ret=(?!0x[0-9a-f]+ == A)", text), \
        "frame-0 plane unexpectedly reused A"
    assert "frame 1 decoded: 64x65 stride=64" in text, "wrong frame-1 dimensions"
    assert "frame 1 encoded rc=0" in text, "encode did not complete"
    assert f"VICTIM fn=0x{fn_hex}" in text, "fn pointer not overwritten with expected bytes"
    assert f"tag[0..7]={tag_hex}" in text, "victim tag mismatch"
    assert f"B-8=0x{header_hex}" in text, "victim chunk header mismatch"
    assert "HEADER A-8=0x8021" in text, "plane chunk header changed"
    return a, b


a, b = inspect(controlled_release, "40" * 8, " ".join(["40"] * 8), "500000500021e")
assert "double free or corruption (!prev)" in controlled_release, "expected release abort"
inspect(controlled_retain, "40" * 8, " ".join(["40"] * 8), "500000500021e")
assert "POST fn=0x" + "40" * 8 in controlled_retain, "retain POST state missing"
assert "corruption" not in controlled_retain, "retain run aborted"
inspect(pattern_retain, "a8" * 8, " ".join(["b6"] * 8), "9c" * 8)
assert "POST fn=0x" + "a8" * 8 in pattern_retain, "patterned POST state missing"
assert "corruption" not in pattern_retain, "patterned retain run aborted"
assert "controlled release rc=134" in rcs and "controlled retain rc=0" in rcs
assert "pattern retain rc=0" in rcs

print("PASS: pad plane reuses adjacent A; live victim fn/tag/header overwritten with file bytes")
print("PASS: encode rc 0; frame-1 release aborts; retained frame exits rc 0 with bytes intact")
print(f"      A={a:#x} B={b:#x} (B-A={b-a:#x})")
