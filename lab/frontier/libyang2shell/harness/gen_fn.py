#!/usr/bin/env python3
"""Extract verbatim functions from pinned libyang sources into harness includes.

Each function is copied byte-for-byte from the pinned file: find its definition
at column zero, brace-match to the closing brace, and emit exactly that slice.
The harness supplies only macros/types/stubs, never a rewritten body.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SRC = ROOT / "src"
OUT = pathlib.Path(__file__).resolve().parent

PINS = {
    "vuln": "979f6925cf1f0918915613022e9e9dfc751bf647",
    "partial": "73da1db8fc14802e4f8fc64d022011a6f9d514db",
    "hardened": "48672b289e2e4c6773712c3ee0abae6b7fffe1f3",
}


def extract(text: str, name: str) -> str:
    marker = "\n" + name + "("
    pos = text.find(marker)
    if pos < 0:
        raise SystemExit(f"function {name} not found")
    # Include the immediately preceding declaration line ("static void",
    # "static LY_ERR", "LIBYANG_API_DEF LY_ERR") verbatim as well.
    prev = text.rfind("\n", 0, pos - 1) + 1
    decl = text[prev:pos - 1]
    start = prev if decl.startswith("static ") or decl.startswith("LIBYANG_API_DEF ") else pos + 1
    brace = text.find("{", pos)
    depth = 0
    for i in range(brace, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return text[start:i + 1]
    raise SystemExit(f"unbalanced braces for {name}")


def main() -> None:
    for label, pin in PINS.items():
        parser = (SRC / f"parser_lyb-{pin}.c").read_text()
        infile = (SRC / "in.c.pin").read_text()
        parts = [
            "/* Verbatim pinned functions, extracted by gen_fn.py; do not edit. */\n",
            "/* parser_lyb.c pin " + pin + " */\n",
        ]
        for name in ("lyb_read", "lyb_read_size", "lyb_read_string"):
            parts.append(extract(parser, name) + "\n\n")
        parts.append("/* src/in.c pin 979f6925 (unchanged ly_in_read helper) */\n")
        parts.append(extract(infile, "ly_in_read") + "\n")
        (OUT / f"fns-{label}.inc").write_text("".join(parts))
        print(f"{label}: {pin} -> fns-{label}.inc")


if __name__ == "__main__":
    main()
