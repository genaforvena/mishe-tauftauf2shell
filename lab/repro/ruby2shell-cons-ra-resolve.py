#!/usr/bin/env python3
"""Resolve mtrace C/P-line return-address chains to symbols (analysis only).

Reads probe logs containing MAPS_BEGIN..MAPS_END dumps plus C/P lines with
ra=<addr>,<addr>,<addr> chains (added 2026-11-25). For each ra that falls in
the main ruby executable, resolves file:line via addr2line; other regions are
reported by map path only.

Usage: ruby2shell-cons-ra-resolve.py <log...>
"""
import re
import subprocess
import sys

RUBY = "lab/build/plain/ruby-3.4.12-plain/bin/ruby"

line_re = re.compile(
    r"^([CP]) tid=(\d+) request=(0x[0-9a-f]+) ptr=(0x[0-9a-f]+) size=(0x[0-9a-f]+)"
    r" ra=(0x[0-9a-fa-f]+),(0x[0-9a-f]+),(0x[0-9a-f]+)")
map_re = re.compile(r"^([0-9a-f]+)-([0-9a-f]+) (\S+) ([0-9a-f]+) \S+ \d+\s*(.*)$")


def addr2line(binary, off):
    try:
        out = subprocess.run(["addr2line", "-e", binary, "-f", "-C", hex(off)],
                             capture_output=True, text=True, timeout=10).stdout.splitlines()
        while len(out) < 2:
            out.append("?")
        return f"{out[0]} @ {out[1]}"
    except Exception as e:
        return f"addr2line-fail {e}"


def resolve(path):
    text = open(path, errors="replace").read()
    mb, me = text.find("MAPS_BEGIN"), text.find("MAPS_END")
    regions = []
    if mb >= 0 and me > mb:
        for line in text[mb + len("MAPS_BEGIN"):me].splitlines():
            m = map_re.match(line)
            if m and "x" in m.group(3):
                regions.append((int(m.group(1), 16), int(m.group(2), 16),
                                int(m.group(4), 16), m.group(5)))
    print(f"## {path}")
    for line in text.splitlines():
        m = line_re.match(line)
        if not m:
            continue
        tag, tid, req, ptr, size, ras = m.group(1), m.group(2), m.group(3), \
            m.group(4), m.group(5), [int(x, 16) for x in m.groups()[5:8]]
        note = " (case-map path)" if req in ("0x222", "0x414") else ""
        print(f" {tag} tid={tid} req={req} ptr={ptr} size={size}{note}")
        for ra in ras:
            if not ra:
                continue
            hit = next((r for r in regions if r[0] <= ra < r[1]), None)
            if not hit:
                print(f"    {ra:#x} -> unmapped")
                continue
            start, end, off, name = hit
            if name.endswith("/bin/ruby"):
                vma = ra - (start - off)
                print(f"    {ra:#x} -> ruby vma {vma:#x} {addr2line(RUBY, vma)}")
            else:
                print(f"    {ra:#x} -> {name or 'anon'} (map {start:#x}-{end:#x} off {off:#x})")


def main():
    for p in sys.argv[1:]:
        resolve(p)


if __name__ == "__main__":
    main()
