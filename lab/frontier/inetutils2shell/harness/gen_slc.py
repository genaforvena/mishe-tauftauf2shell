#!/usr/bin/env python3
"""Extract start_slc() and add_slc() verbatim from pinned telnetd/slc.c."""
import sys


def extract(src: str, name: str) -> str:
    start = src.index(name)
    prior = src.rfind("\nvoid\n", 0, start)
    if prior != -1:
        start = prior + 1
    brace = src.index("{", start)
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1] + "\n"
    raise ValueError(name)


def main() -> None:
    pinned, out = sys.argv[1], sys.argv[2]
    with open(pinned, "r", encoding="utf-8") as fh:
        src = fh.read()
    parts = [
        "// VERBATIM pinned functions from " + pinned,
        extract(src, "start_slc (int getit)"),
        extract(src, "add_slc (char func, char flag, cc_t val)"),
    ]
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))


if __name__ == "__main__":
    main()
