#!/usr/bin/env python3
"""Extract msgpack_vrefbuffer_migrate() byte-for-byte from a pinned source."""
import pathlib
import sys


def extract(src, out, name="msgpack_vrefbuffer_migrate"):
    text = pathlib.Path(src).read_text()
    start = text.index("int " + name + "(")
    brace = text.index("{", start)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                pathlib.Path(out).write_text(text[start:i + 1] + "\n")
                return text[start:i + 1]
    raise SystemExit("unbalanced braces in " + src)


if __name__ == "__main__":
    body = extract(sys.argv[1], sys.argv[2])
    print("EXTRACTED", len(body), "bytes", sys.argv[2])
