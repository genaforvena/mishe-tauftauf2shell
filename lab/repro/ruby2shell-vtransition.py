#!/usr/bin/env python3
"""Analyze MTRACE_DUMP_RANGE D2 lines for a grown victim's link transitions.

Usage: python3 lab/repro/ruby2shell-vtransition.py TAG [LABEL]
Reads lab/build/evidence/<label>-<tag>-*.server.log; for each run it finds the
last B snapshot (the grown victim) and prints compressed D2 states after it:
the seq/req where vsize/vfd/vbk/bin links changed, and the first 0x400-0x460
malloc/C line following each change. Analysis only; no target behavior depends
on it.
"""
import glob
import re
import sys

label = sys.argv[2] if len(sys.argv) > 2 else "stock-sinatra"
tag = sys.argv[1]
logs = sorted(
    glob.glob(f"lab/build/evidence/{label}-{tag}-*.server.log"),
    key=lambda p: int(re.search(r"-(\d+)\.server\.log$", p).group(1)),
)
for log in logs:
    run = re.search(r"-(\d+)\.server\.log$", log).group(1)
    lines = open(log, errors="replace").read().splitlines()
    bpos = max((i for i, l in enumerate(lines) if l.startswith("B ")), default=-1)
    if bpos < 0:
        print(f"run {run}: no B snapshot")
        continue
    b = lines[bpos]
    victim = re.search(r"victim=(0x[0-9a-f]+)", b).group(1)
    vhdr = hex(int(victim, 16) - 0x10)
    fields = ("vsize", "vfd", "vbk", "fd", "bk", "vfdnext", "vbknext")
    states = []
    for i in range(bpos + 1, len(lines)):
        l = lines[i]
        if not l.startswith("D2 "):
            continue
        parts = l.split()
        if parts[2].startswith("vhdr="):
            continue
        f = dict(kv.split("=", 1) for kv in parts[2:])
        if f.get("vhdr") != vhdr:
            continue
        state = tuple(f.get(k) for k in fields)
        if not states or state != states[-1][3]:
            states.append((i, f["nb"], i, state))
    print(f"run {run}: victim={victim} B={re.search(r'size=(0x[0-9a-f]+)', b).group(1)} "
          f"D2-states={len(states)}")
    for n, (pos0, req, pos, st) in enumerate(states):
        until = states[n + 1][0] if n + 1 < len(states) else "-"
        follow = "-"
        for l in lines[pos + 1:]:
            m = re.match(r"^[MC] (?:tid=\d+ )?request=(0x[0-9a-f]+)", l) or \
                re.match(r"^[MC] 0 ([0-9a-f]+) ", l)
            if m and 0x400 <= int(m.group(1), 16) <= 0x460:
                follow = l[:120]
                break
        print(f"  line={pos0:<7} nb={req:<6} until={until} "
              f"vsize={st[0]} vfd={st[1]} vbk={st[2]} "
              f"binfd={st[3]} binbk={st[4]} next={st[5]}/{st[6]} "
              f"then: {follow}")
