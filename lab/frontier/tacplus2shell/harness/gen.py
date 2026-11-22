#!/usr/bin/env python3
"""Extract verbatim pinned functions into an include file for the C harness.

Reads the committed pinned blobs in ../pins/ so the harness is self-contained in
a clean git archive (no source clone or .git needed). Line ranges are checked
against those blobs; extracted text is emitted byte-for-byte, never retyped.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PINS = os.path.join(os.path.dirname(HERE), "pins")

CASES = {
    "vuln": ("packet-vuln.c", "author-vuln.c"),
    "fixed": ("packet-fixed.c", "author-fixed.c"),
}

# validator functions: author 511-524, accounting 526-539
PACKET_RANGES = [(511, 524), (526, 539)]
AUTHOR_RANGE = (66, 97)


def extract(text, start, end):
    lines = text.splitlines()
    return "\n".join(lines[start - 1:end])


def main():
    case = sys.argv[1]
    packet_file, author_file = CASES[case]
    out = []
    with open(os.path.join(PINS, packet_file)) as f:
        packet = f.read()
    with open(os.path.join(PINS, author_file)) as f:
        author = f.read()
    for a, b in PACKET_RANGES:
        out.append(f"/* verbatim {case}:tac_plus-ng/packet.c:{a}-{b} */")
        out.append(extract(packet, a, b))
    a, b = AUTHOR_RANGE
    out.append(f"/* verbatim {case}:tac_plus-ng/author.c:{a}-{b} */")
    out.append(extract(author, a, b))
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
