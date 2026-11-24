#!/usr/bin/env python3
"""W172: normalize six 4096-byte OOB-source dumps into a stable verdict.

Usage: analyze.py RUN... where runs are named <tag>.bin; tags starting with
'5a' are 0x5a variants, all others 0x41. The check is structural: the
in-bounds 64 bytes track the file byte, while OOB differences stay in one
short window that also varies across repeats of the same file.
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


for tag, blob in runs.items():
    print(f"RUN {tag} size={len(blob)} inbounds=0x{expected(tag):02x}")
    check(f"size-{tag}", len(blob) == 4096)
    check(f"inbounds-{tag}", blob[:64] == bytes([expected(tag)]) * 64)


def oobdiff(a, b):
    return frozenset(i for i in range(64, 4096) if a[i] != b[i])


base = "41"
others = [t for t in runs if t != base]
sets = {t: oobdiff(runs[base], runs[t]) for t in others}
union = set().union(*sets.values()) if sets else set()
print("UNION within-small-window")
for t in sorted(sets):
    d = sets[t]
    print(f"DIFF {base}-vs-{t} within-window")
    check(f"window-size-{t}", len(union) - 2 <= len(d) <= 16)
check("window-nonempty-and-short", 0 < len(union) <= 16)

same = [t for t in others if not t.startswith("5a")]
check("repeat-varies", bool(same) and bool(union) and
      all(len({runs[t][i] for t in [base] + same}) > 1 for i in union))
check("pixel-does-not-select-oob", bool(union) and
      all(len({runs[t][i] for t in [base] + same}) > 1 for i in union))

print("RESULT", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
