#!/usr/bin/env python3
"""W179: assert the vulnerable / safe / fixed pointer-control triad.

Usage: check_pointer.py EVIDENCE_DIR
Evidence is produced by real/run_pointer.sh.
"""
import re
import sys
from pathlib import Path

out = Path(sys.argv[1])
texts = {k: (out / f"{k}.out").read_text() for k in ("attack", "safe", "fixed")}
rcs = {k: (out / f"{k}.rc").read_text().strip() for k in ("attack", "safe", "fixed")}
checks = []

def check(name, ok):
    checks.append((name, bool(ok)))

check("attack_rc0", rcs["attack"] == "0")
check("safe_rc0", rcs["safe"] == "0")
check("fixed_rc0", rcs["fixed"] == "0")
check("plane_reuses_A", bool(re.search(r"CALLOC32783 count=2 ret=0x[0-9a-f]+ == A", texts["attack"])))

post = re.search(r"POST fn=(0x[0-9a-f]+) expected=(0x[0-9a-f]+)", texts["attack"])
check("post_pointer_present", post is not None)
if post:
    check("file_pointer_is_target", post.group(1) == post.group(2))
    victim = re.search(r"VICTIM fn=(0x[0-9a-f]+)", texts["attack"])
    check("victim_matches_post", victim is not None and victim.group(1) == post.group(1))
    check("valid_nonpie_address", int(post.group(1), 16) > 0x400000)
check("neighbour_size_preserved", "HEADER B-8=0x8021" in texts["attack"])
check("benign_marker_executed", "BENIGN_MARKER_CALLED" in texts["attack"])
check("attack_no_control_marker", "CONTROL_FN_UNCHANGED" not in texts["attack"])

safe_post = re.search(r"POST fn=(0x[0-9a-f]+) expected=(0x[0-9a-f]+)", texts["safe"])
check("safe_fn_differs_from_target", safe_post is not None and
      safe_post.group(1) != safe_post.group(2))
check("safe_no_benign_marker", "BENIGN_MARKER_CALLED" not in texts["safe"])
check("safe_control_marker", "CONTROL_FN_UNCHANGED" in texts["safe"])
check("fixed_no_benign_marker", "BENIGN_MARKER_CALLED" not in texts["fixed"])
check("fixed_control_marker", "CONTROL_FN_UNCHANGED" in texts["fixed"])

for name, ok in checks:
    print(f"{'PASS' if ok else 'FAIL'} {name}")
passed = sum(ok for _, ok in checks)
print(f"PASS={passed} FAIL={len(checks) - passed}")
sys.exit(0 if all(ok for _, ok in checks) else 1)
