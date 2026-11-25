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
pat = re.compile(r"^([BACVPQG]) ")


def parse(logpath):
    out = {"B": [], "A": [], "C": [], "V": [], "P": [], "Q": [], "G": []}
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
    logs = sorted(glob.glob(os.path.join(EV, "stock-rails-cons-vis-*.server.log")))
    if not sys.argv[1:] == []:
        logs = [p for p in logs if re.search(sys.argv[1], p)]
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
        rows.append((tag, alive,
                     bsize.group(1) if bsize else "-",
                     asize.group(1) if asize else "-",
                     len(d["C"]), g251, len(d["P"]), len(d["Q"])))
    print(f"{'tag':24} {'alive':5} {'B':7} {'A':7} C  q38=0x251 P  Q")
    for r in rows:
        print(f"{r[0]:24} {r[1]:5} {r[2]:7} {r[3]:7} {r[4]}  {str(r[5]):9} {r[6]}  {r[7]}")
    n = len(rows)
    print(f"\nruns={n} alive={sum(1 for r in rows if r[1]=='YES')} "
          f"expanded_C={sum(1 for r in rows if r[4]>0)} "
          f"q38_0x251={sum(1 for r in rows if r[5])} "
          f"with_P={sum(1 for r in rows if r[6]>0)} "
          f"with_Q={sum(1 for r in rows if r[7]>0)}")


if __name__ == "__main__":
    main()
