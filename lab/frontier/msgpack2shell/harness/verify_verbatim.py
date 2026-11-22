#!/usr/bin/env python3
"""Assert each generated function slice is an exact substring of its pin."""
import pathlib
import sys


def verify(inc, src):
    body = pathlib.Path(inc).read_text().rstrip("\n")
    text = pathlib.Path(src).read_text()
    if body not in text:
        raise SystemExit("NOT VERBATIM: " + inc)
    print("VERBATIM OK", inc, len(body), "bytes")


if __name__ == "__main__":
    verify(sys.argv[1], sys.argv[2])
