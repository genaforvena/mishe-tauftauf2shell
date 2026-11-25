#!/usr/bin/env python3
"""Classify wire-leaked reflected pointers against a post-response
/proc/PID/maps snapshot (analysis only).

For every lab/build/evidence/stock-rails-<prefix>*.html with a matching
.maps file, parses the reflected multipart params, finds pointer-shaped
qwords (ruby2shell-reflect-scan.py's MMAP_PTR class), and reports the
mapping label and offset of each, plus the mtrace B-line victim address
from the run's server log for region correlation.

Usage: ruby2shell-leak-maps.py <tag-prefix>
"""
import glob
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
EV = os.path.join(HERE, "..", "build", "evidence")
SCAN = os.path.join(HERE, "ruby2shell-reflect-scan.py")


def load_scan_ns():
    src = open(SCAN).read()
    ns = {"__file__": SCAN}
    exec(src.split("def main():")[0], ns)
    return ns


def load_maps(path):
    out = []
    with open(path) as f:
        for line in f:
            r = line.split()
            lo, hi = (int(x, 16) for x in r[0].split("-"))
            label = " ".join(r[5:]) if len(r) > 5 else "[anon]"
            out.append((lo, hi, r[1], label))
    return out


def where(maps, addr):
    for lo, hi, perms, label in maps:
        if lo <= addr < hi:
            return label, addr - lo, perms, lo
    return None, None, None, None


def main():
    prefix = sys.argv[1] if len(sys.argv[1:]) else "leakclass-"
    ns = load_scan_ns()
    files = sorted(glob.glob(os.path.join(EV, f"stock-rails-{prefix}*.html")))
    if not files:
        print(f"no html for prefix {prefix!r}")
        sys.exit(2)
    total = leaks = 0
    for path in files:
        tag = os.path.basename(path).split("stock-rails-")[1].split(".html")[0]
        mapspath = path.replace(".html", ".maps")
        if not os.path.exists(mapspath):
            continue
        total += 1
        text = open(path, encoding="utf-8", errors="replace").read()
        parts = list(ns["parse_params"](text))
        if not parts:
            continue
        maps = load_maps(mapspath)
        victim = None
        try:
            with open(path.replace(".html", ".server.log"), errors="replace") as f:
                for line in f:
                    if line.startswith("B "):
                        m = re.search(r"victim=(0x[0-9a-f]+)", line)
                        if m:
                            victim = int(m.group(1), 16)
                        break
        except FileNotFoundError:
            pass
        vmap = where(maps, victim) if victim else (None,)*4
        found = []
        for name, val in parts:
            for lo, q, _c in ns["leak_windows"](val, name):
                found.append((name, lo, q))
        if not found:
            print(f"{tag}: no reflected pointers (victim="
                  f"{hex(victim) if victim else '?'} in {vmap[0]})")
            continue
        leaks += 1
        print(f"{tag}: victim={hex(victim) if victim else '?'} "
              f"in {vmap[0]} +{vmap[1]:#x}" if victim else f"{tag}:")
        for name, lo, q in found:
            label, off, perms, base = where(maps, q)
            delta = f"{q - victim:+#x}" if victim else "?"
            print(f"  {name}+{lo} 0x{q:016x} -> {label} +{off:#x} {perms} "
                  f"(map base {base:#x}, delta-from-victim {delta})")
    print(f"\nsurvivor-htmls-with-maps={total} with-leaks={leaks}")


if __name__ == "__main__":
    main()
