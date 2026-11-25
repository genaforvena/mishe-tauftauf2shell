#!/usr/bin/env python3
"""Tabulate the consumer-visibility batch (analysis only).

Reads lab/build/evidence/stock-rails-cons-vis-*.server.log and reports per
run: B/A victim sizes, G-window qwords, C (second-buffer consumption of V),
P (allocation returning into the forged window), Q (free of a window user
pointer), plus survival from the matching .out file.
"""
import glob
import os
import re
import sys

EV = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "build", "evidence")
pat = re.compile(r"^([BACVPQGH]) ")


def parse(logpath):
    out = {"B": [], "A": [], "C": [], "V": [], "P": [], "Q": [], "G": [], "H": []}
    try:
        with open(logpath, errors="replace") as f:
            for line in f:
                m = pat.match(line)
                if m:
                    out[m.group(1)].append(line.rstrip())
    except FileNotFoundError:
        pass
    return out


def main():
    if sys.argv[1:]:
        logs = sorted(glob.glob(os.path.join(EV, f"stock-rails-{sys.argv[1]}*.server.log")))
    else:
        logs = sorted(glob.glob(os.path.join(EV, "stock-rails-cons-vis-*.server.log")))
    if sys.argv[2:]:
        logs = [p for p in logs if re.search(sys.argv[2], p)]
    rows = []
    for logpath in logs:
        tag = os.path.basename(logpath).split("stock-rails-")[1].split(".server.log")[0]
        d = parse(logpath)
        outpath = logpath.replace(".server.log", ".out")
        alive = "?"
        try:
            with open(outpath) as f:
                alive = "YES" if "alive-after-trigger=YES" in f.read() else "NO"
        except FileNotFoundError:
            pass
        b = d["B"][0] if d["B"] else ""
        a = d["A"][0] if d["A"] else ""
        bsize = re.search(r" size=(0x[0-9a-f]+)", b)
        asize = re.search(r" size=(0x[0-9a-f]+)", a)
        g251 = any("q38=0x251" in g for g in d["G"])
        bs = int(bsize.group(1), 16) if bsize else 0
        az = int(asize.group(1), 16) if asize else 0
        kind = "-" if not (bs and az) else (
            "EXPAND" if (az & ~7) > (bs & ~7) else
            ("shrink" if (az & ~7) < (bs & ~7) else "flag"))
        rows.append((tag, alive, kind,
                     bsize.group(1) if bsize else "-",
                     asize.group(1) if asize else "-",
                     len(d["C"]), g251, len(d["P"]), len(d["Q"]), len(d["H"])))
    print(f"{'tag':24} {'alive':5} {'kind':6} {'B':7} {'A':7} C  q38=0x251 P  Q  H")
    for r in rows:
        print(f"{r[0]:24} {r[1]:5} {r[2]:6} {r[3]:7} {r[4]:7} {r[5]}  {str(r[6]):9} {r[7]}  {r[8]}  {r[9]}")
    n = len(rows)
    print(f"\nruns={n} alive={sum(1 for r in rows if r[1]=='YES')} "
          f"expand={sum(1 for r in rows if r[2]=='EXPAND')} "
          f"with_C={sum(1 for r in rows if r[5]>0)} "
          f"q38_0x251={sum(1 for r in rows if r[6])} "
          f"with_P={sum(1 for r in rows if r[7]>0)} "
          f"with_Q={sum(1 for r in rows if r[8]>0)} "
          f"with_H={sum(1 for r in rows if r[9]>0)}")


if __name__ == "__main__":
    main()
