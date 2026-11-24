#!/usr/bin/env python3
"""W174: does a large earlier valid chunk put file bytes in the OOB source?

Usage: analyze_large.py src-<tag>.bin ... ; tags starting with '5a' carry
pixel byte 0x5a, all others 0x41. A positive needs at least one offset >= 64
where every 0x41 run reads 0x41, every 0x5a run reads 0x5a, and the two 0x41
repeats agree (so the difference is not run-to-run allocator residue).
"""
import sys
from pathlib import Path

runs = {Path(arg).name.removeprefix("src-").removesuffix(".bin"): Path(arg).read_bytes()
        for arg in sys.argv[1:]}
ok = True


def check(name, cond, detail=""):
    global ok
    print(("PASS " if cond else "FAIL ") + name + (" " + detail if detail else ""))
    ok = ok and cond


def expected(tag):
    return 0x5a if tag.startswith("5a") else 0x41


hi = [t for t in runs if t.startswith("5a")]
lo = [t for t in runs if not t.startswith("5a")]
check("two-variants", len(hi) >= 1 and len(lo) >= 2, f"41={sorted(lo)} 5a={sorted(hi)}")
for tag, blob in sorted(runs.items()):
    print(f"RUN {tag} size={len(blob)} inbounds=0x{expected(tag):02x}")
    check(f"size-{tag}", len(blob) == 4096)
    check(f"inbounds-{tag}", blob[:64] == bytes([expected(tag)]) * 64)

if len(hi) >= 1 and len(lo) >= 2:
    tracked = []
    diff = []
    for i in range(64, 4096):
        lo_vals = {runs[t][i] for t in lo}
        hi_vals = {runs[t][i] for t in hi}
        if lo_vals == {0x41} and hi_vals == {0x5a}:
            tracked.append(i)
        if lo_vals != hi_vals:
            diff.append(i)
    print(f"OOB tracked={len(tracked)} differing={len(diff)}")
    if tracked:
        print("TRACKED first=", tracked[:16])
    if diff:
        print("DIFF first=", diff[:16])
    # Negative verdict: no OOB offset tracks the file byte.
    check("no-file-byte-in-oob", not tracked)
    check("difference-window-short", len(diff) <= 32, f"count={len(diff)}")

print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
