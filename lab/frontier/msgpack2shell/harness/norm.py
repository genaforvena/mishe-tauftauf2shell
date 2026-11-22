#!/usr/bin/env python3
"""Normalize one harness log: keep evidence lines, erase volatile fields."""
import pathlib
import re
import sys

KEEP = (
    "ERROR: AddressSanitizer", "WRITE of size", "is located",
    "allocated by thread", "SUMMARY: AddressSanitizer",
    "IN[", "CHOSEN", "EXTRACTED", "VERBATIM",
    "in msgpack_vrefbuffer_migrate", "in memcpy", "in run_vuln",
)
RULES = (
    (re.compile(r"0x[0-9a-fA-F]+"), "0xADDR"),
    (re.compile(r"==\d+=="), "==PID=="),
    (re.compile(r"\(BuildId [0-9a-f]+\)"), "(BUILDID)"),
    (re.compile(r"/[^\s:()]*/([^\s:()/]+\.(?:c|inc|h|cpp))"), r"\1"),
    (re.compile(r"/[^\s()]+/([^\s()]+)(?:\+0xADDR)?"), r"BINARY"),
    (re.compile(r"\s+"), " "),
)


def norm(text):
    out = []
    for line in text.splitlines():
        if not any(k in line for k in KEEP):
            continue
        for pat, rep in RULES:
            line = pat.sub(rep, line)
        line = line.strip()
        if line and line not in out:
            out.append(line)
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    pathlib.Path(sys.argv[2]).write_text(norm(pathlib.Path(sys.argv[1]).read_text(errors="replace")))
