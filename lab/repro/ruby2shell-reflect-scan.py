#!/usr/bin/env python3
"""Scan stock-Rails 404 HTML for reflected-param corruption (analysis only).

The development routing-error page renders every multipart parameter
verbatim as an inspect-escaped String inside the params <pre> block. This
tool byte-diffs each reflected value against the body the driver generated
(drain/filler pattern or plain filler bytes) and reports every deviation
plus any little-endian qword inside a value that has a glibc heap-pointer
or libc-pointer shape -- the wire-visible oracle signature the carve-
landing experiment is looking for.

Usage:
  ruby2shell-reflect-scan.py <tag-prefix> [--n 524] [--fill-len 256]
      [--drain-len 1024] [--pattern 250,90] [--filler-plain]
      [--html-glob GLOB]

Reads lab/build/evidence/stock-rails-<tag-prefix>*.html.
"""
import argparse
import glob
import html
import os
import re
import sys

EV = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                  "..", "build", "evidence")

INSPECT_ESC = re.compile(
    rb"\\x([0-9A-Fa-f]{2})|\\n|\\t|\\r|\\f|\\v|\\e|\\a|\\b|\\s|\\\\|\\\"|\\'|\\")


def unescape_inspect(raw: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(raw):
        if raw[i:i + 1] == b"\\" and i + 1 < len(raw):
            two = raw[i:i + 2]
            if len(two) == 2 and two[1] in b"ntrfv easb":
                mapping = {b"\\n": 0x0a, b"\\t": 0x09, b"\\r": 0x0d,
                           b"\\f": 0x0c, b"\\v": 0x0b, b"\\e": 0x1b,
                           b"\\a": 0x07, b"\\b": 0x08, b"\\s": 0x20}
                if two in mapping:
                    out.append(mapping[two])
                    i += 2
                    continue
            if raw[i:i + 2].lower() == b"\\x" and i + 3 < len(raw) + 1:
                hexb = raw[i + 2:i + 4]
                if len(hexb) == 2:
                    try:
                        out.append(int(hexb, 16))
                        i += 4
                        continue
                    except ValueError:
                        pass
            out.append(raw[i + 1])
            i += 2
            continue
        out.append(raw[i])
        i += 1
    return bytes(out)


def classify(q: int) -> str:
    """High-mapping userspace pointers (this host maps binaries/heap at
    0x7d.. and libs/GC pages at 0x7e/0x7f..) or a small size field."""
    if 0x700000000000 <= q < 0x800000000000 and (q & 0xfff) != 0:
        return "MMAP_PTR"
    if q and (q >> 32) == 0 and q & 0xf in (1, 3, 5, 7) and (q & ~0xf) < 0x20000:
        return "SIZE_LIKE"
    return "OTHER"


def qword(b: bytes, off: int) -> int:
    chunk = b[off:off + 8]
    return int.from_bytes(chunk.ljust(8, b"\0"), "little")


def leak_windows(b: bytes, name: str):
    hits = []
    for off in range(0, max(1, len(b) - 7)):
        q = qword(b, off)
        c = classify(q)
        if c == "MMAP_PTR":
            hits.append((off, q, c))
    return hits


def parse_params(text: str):
    """Yield (name, unescaped bytes) for every reflected String param."""
    # Values sit on a single PP.pp line:  "name" =>\n  "value",\n
    # The last param closes the hash: "value"}\n  — no DOTALL so the
    # value match cannot run past its own line.
    pat = re.compile(r'&quot;([^&]+)&quot; =&gt;\n {2}&quot;(.*?)&quot;(?:,|\})\n')
    for m in pat.finditer(text):
        name = html.unescape(m.group(1))
        val = html.unescape(m.group(2))
        yield name, unescape_inspect(val.encode("utf-8", "surrogateescape"))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("prefix")
    ap.add_argument("--n", type=int, default=524)
    ap.add_argument("--fill-len", type=int, default=256)
    ap.add_argument("--drain-len", type=int, default=1024)
    ap.add_argument("--pattern", default="0x250,0x90")
    ap.add_argument("--filler-plain", action="store_true")
    ap.add_argument("--html-glob", default=None)
    args = ap.parse_args()

    prev, nxt = (int(v, 0) for v in args.pattern.split(",", 1))
    pat8 = prev.to_bytes(8, "little") + nxt.to_bytes(8, "little")
    drains = bytearray((pat8 * ((args.drain_len + 15) // 16))[:args.drain_len])
    filler = (b"f" * args.fill_len if args.filler_plain else
              bytearray((pat8 * ((args.fill_len + 15) // 16))[:args.fill_len]))
    method = bytearray(b"a" + b"\xdf" * (args.n - 1))

    if args.html_glob:
        files = sorted(glob.glob(args.html_glob))
    else:
        files = sorted(glob.glob(os.path.join(
            EV, f"stock-rails-{args.prefix}*.html")))
    if not files:
        print(f"no html for prefix {args.prefix!r}")
        sys.exit(2)

    total_parts = total_hits = total_leaks = 0
    files_with_hits = []
    for path in files:
        tag = os.path.basename(path).split("stock-rails-")[1].split(".html")[0]
        text = open(path, encoding="utf-8", errors="replace").read()
        parts = list(parse_params(text))
        dev = []
        leaks = []
        for name, val in parts:
            total_parts += 1
            if name.startswith("d"):
                exp = drains
            elif name == "f":
                exp = filler
            elif name == "_method":
                # raw request value, tail varies per run: pointer-scan only
                for lo, q, c in leak_windows(val, name):
                    leaks.append((name, lo, q, c))
                continue
            else:
                continue
            for lo, q, c in leak_windows(val, name):
                leaks.append((name, lo, q, c))
            if val == exp:
                continue
            # first differing offset
            off = next((i for i in range(min(len(val), len(exp)))
                        if val[i] != exp[i]), None)
            dev.append((name, off, len(val)))
        if dev or leaks:
            files_with_hits.append(tag)
        for name, off, ln in dev[:6]:
            print(f"{tag}: DEVIATE {name} at byte {off} (len {ln})")
        for name, lo, q, c in leaks[:6]:
            print(f"{tag}: LEAKSHAPE {name}+{lo} q=0x{q:016x} {c}")
        total_hits += len(dev)
        total_leaks += len(leaks)
        status = "clean" if not (dev or leaks) else "DEVIATE/LEAK"
        print(f"{tag}: parts={len(parts)} deviate={len(dev)} "
              f"leakshape={len(leaks)} {status}")

    print(f"\nfiles={len(files)} parts={total_parts} deviations={total_hits} "
          f"leakshapes={total_leaks} files_with_findings={len(files_with_hits)}")
    if files_with_hits:
        print("tags:", " ".join(files_with_hits))


if __name__ == "__main__":
    main()
