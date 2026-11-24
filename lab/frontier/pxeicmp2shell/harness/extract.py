#!/usr/bin/env python3
"""Extract the two DPC handlers verbatim from the pinned EDK2 files.

Brace matching starts at the signature anchor and ends at the function's
closing brace. The extracted text is byte-for-byte a substring of the pin;
extract-index.txt records offsets and SHA-256 so a witness can recheck.
"""
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS = ROOT / "pins"
OUT = ROOT / "harness" / "generated"
OUT.mkdir(parents=True, exist_ok=True)

ANCHORS = (
    "VOID\nEFIAPI\nPxeBcIcmpErrorDpcHandle (",
    "VOID\nEFIAPI\nPxeBcIcmp6ErrorDpcHandle (",
)
NAMES = ("v4", "v6")


def extract(src: str, anchor: str):
    if "\r\n" in src:
        anchor = anchor.replace("\n", "\r\n")
    start = src.index(anchor)
    brace = src.index("{", start)
    depth = 0
    for i in range(brace, len(src)):
        if src[i] == "{":
            depth += 1
        elif src[i] == "}":
            depth -= 1
            if depth == 0:
                return start, i + 1, src[start:i + 1]
    raise ValueError("unbalanced braces")


index = []
for variant in ("vuln", "fixed"):
    data = (PINS / f"PxeBcSupport.c.{variant}").read_bytes().decode("utf-8")
    pieces = []
    for name, anchor in zip(NAMES, ANCHORS):
        start, end, text = extract(data, anchor)
        assert text in data
        pieces.append(text)
        index.append(
            f"{variant} {name} source={hashlib.sha256(data.encode()).hexdigest()} "
            f"span=[{start},{end}) sha256={hashlib.sha256(text.encode()).hexdigest()} "
            f"bytes={len(text)}"
        )
    header = f'/* Verbatim extraction from pins/PxeBcSupport.c.{variant}; see extract-index.txt. */\n#include "standin.h"\n'
    (OUT / f"handlers_{variant}.c").write_text(header + "\n\n".join(pieces) + "\n")

(OUT / "extract-index.txt").write_text("\n".join(index) + "\n")
print("\n".join(index))
