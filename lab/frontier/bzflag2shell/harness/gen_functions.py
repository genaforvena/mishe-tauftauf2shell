#!/usr/bin/env python3
"""Extract the two verbatim pinned NetHandler functions used by the harness.

Usage: gen_functions.py PINNED_NetHandler.cxx OUTPUT.inc
The output keeps the exact bytes of each function from the pinned source.
"""
import sys


def extract(src: str, signature: str) -> str:
    start = src.index(signature)
    brace = src.index("{", start)
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return src[start:i + 1] + "\n"
    raise ValueError("unbalanced function " + signature)


def main() -> None:
    pinned, out = sys.argv[1], sys.argv[2]
    with open(pinned, "r", encoding="utf-8") as fh:
        src = fh.read()
    parts = [
        "// VERBATIM pinned function bodies extracted from",
        "// " + pinned,
        "// by harness/gen_functions.py; no hand edits to the function text.",
        extract(src, "RxStatus NetHandler::tcpReceive()"),
        extract(src, "RxStatus NetHandler::receive(size_t length, bool *retry)"),
    ]
    with open(out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(parts))


if __name__ == "__main__":
    main()
