#!/usr/bin/env python3
"""Deterministically decode an sqlite3 `.open --hexdb` transcript to a DB file.

Only `| size N pagesize P`, `| page K offset O`, `| X: aa bb ...` and `| end`
are consumed; offsets are decimal, sparse gaps are zero-filled. No network,
no subprocesses, no dependence on the sqlite3 shell.
"""
import re
import sys

SIZE_RE = re.compile(r"^\|\s*size\s+(\d+)\s+pagesize\s+(\d+)")
PAGE_RE = re.compile(r"^\|\s*page\s+(\d+)\s+offset\s+(\d+)")
BYTE_RE = re.compile(r"^\|\s*([0-9]+):\s*((?:[0-9a-fA-F]{2}(?:\s+|$))+)")


def decode(src, dst):
    size = pagesize = base = None
    out = None
    seen_pages = []
    with open(src, "r", encoding="ascii") as fh:
        for lineno, raw in enumerate(fh, 1):
            line = raw.rstrip("\n")
            m = SIZE_RE.match(line)
            if m:
                if out is not None:
                    raise ValueError("line %d: duplicate size" % lineno)
                size, pagesize = int(m.group(1)), int(m.group(2))
                out = bytearray(size)
                continue
            m = PAGE_RE.match(line)
            if m:
                page, base = int(m.group(1)), int(m.group(2))
                if base != (page - 1) * pagesize:
                    raise ValueError("line %d: page/offset mismatch" % lineno)
                seen_pages.append(page)
                continue
            m = BYTE_RE.match(line)
            if m:
                if out is None or base is None:
                    raise ValueError("line %d: byte line before page" % lineno)
                off = int(m.group(1), 10)
                data = bytes.fromhex(m.group(2))
                if off + len(data) > pagesize:
                    raise ValueError("line %d: line overruns page" % lineno)
                start = base + off
                out[start:start + len(data)] = data
                continue
            if line.startswith((".", "| ")):
                # `.open --hexdb`, `| end` and unrecognised metadata lines
                # are intentionally ignored.
                continue
            if line.strip():
                raise ValueError("line %d: unrecognised line: %r" % (lineno, line))
    if out is None or size % pagesize:
        raise ValueError("missing or inconsistent size/pagesize")
    if not seen_pages or max(seen_pages) * pagesize > size:
        raise ValueError("bad page set")
    with open(dst, "wb") as fh:
        fh.write(out)
    return size, pagesize, seen_pages


if __name__ == "__main__":
    sz, ps, pages = decode(sys.argv[1], sys.argv[2])
    print("decoded size=%d pagesize=%d pages=%s" % (sz, ps, ",".join(map(str, pages))))
