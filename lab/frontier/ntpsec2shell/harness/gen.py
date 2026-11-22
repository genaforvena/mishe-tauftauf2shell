#!/usr/bin/env python3
"""Extract extens_client_recv() byte-for-byte from the pinned NTPsec files.

Only the function body, NONCE_LENGTH/CMAC_LENGTH defines and the two pinned
buffer helpers are copied. Structs, counters and the driver are local stubs.
"""
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PINS = ROOT / "pins"
OUT = pathlib.Path(__file__).resolve().parent / "fn.inc"


def extract_function(text, marker):
    lines = text.splitlines(keepends=True)
    start = next(i for i, ln in enumerate(lines) if ln.startswith(marker))
    end = next(i for i in range(start + 1, len(lines)) if lines[i] == "}\n")
    return "".join(lines[start:end + 1])


def extract_line(text, marker):
    return next(ln for ln in text.splitlines(keepends=True) if ln.startswith(marker))


def main():
    which = sys.argv[1]
    assert which in ("vuln", "fixed")
    src = (PINS / f"nts_extens-{which}.c").read_text()
    nts = (PINS / "nts-vuln.c").read_text()
    parts = [
        "/* GENERATED from pinned NTPsec sources; do not edit. */\n",
        extract_line(src, "#define NONCE_LENGTH"),
        extract_line(src, "#define CMAC_LENGTH"),
        "\n/* buffer helpers verbatim from pinned NTPsec_1_2_4 ntpd/nts.c */\n",
        extract_function(nts, "uint16_t ex_next_record("),
        "\n",
        extract_function(nts, "uint16_t next_uint16("),
        "\n/* verbatim from pinned ntpd/nts_extens.c */\n",
        extract_function(src, "bool extens_client_recv("),
        "\n",
    ]
    OUT.write_text("".join(parts))
    print(f"extracted {which} extens_client_recv into {OUT}")


if __name__ == "__main__":
    main()
