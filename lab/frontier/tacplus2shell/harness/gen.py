#!/usr/bin/env python3
"""Extract verbatim pinned functions into an include file for the C harness.

Line ranges are checked against the pinned blobs (git show <pin>:<path>); the
extracted text is emitted byte-for-byte, never retyped.
"""
import subprocess
import sys

ROOT = __import__("os").path.dirname(__import__("os").path.dirname(
    __import__("os").path.abspath(__file__)))
SRC = ROOT + "/src"

CASES = {
    "vuln": "929671c22ff9f390f22decd7eb97dffaece8aebe",
    "fixed": "d8493e0d6420b91737fa34c2cd7bbd365d023b5b",
}

EXPECT = {
    "tac_plus-ng/author.c": (66, 97),
}

# validator functions: author 511-524, accounting 526-539
RANGES = {
    "vuln": {
        "tac_plus-ng/packet.c": [(511, 524), (526, 539)],
    },
    "fixed": {
        "tac_plus-ng/packet.c": [(511, 524), (526, 539)],
    },
}


def blob(pin, path):
    return subprocess.check_output(["git", "-C", SRC, "show", f"{pin}:{path}"]).decode()


def extract(text, start, end):
    lines = text.splitlines()
    return "\n".join(lines[start - 1:end])


def main():
    case = sys.argv[1]
    pin = CASES[case]
    out = []
    for path, ranges in RANGES[case].items():
        text = blob(pin, path)
        for a, b in ranges:
            out.append(f"/* verbatim {pin}:{path}:{a}-{b} */")
            out.append(extract(text, a, b))
    text = blob(pin, "tac_plus-ng/author.c")
    a, b = EXPECT["tac_plus-ng/author.c"]
    out.append(f"/* verbatim {pin}:tac_plus-ng/author.c:{a}-{b} */")
    out.append(extract(text, a, b))
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
