#!/usr/bin/env python3
"""Lint README.md structure and the achievement table.

Exit 0 GREEN, 2 RED. System 0 check: no model, no repair, exact rules.
It parses the achievement table as a contiguous block and catches the real
failure modes: an orphan row, a blank line inside the block, a prose line
that starts before the table has ended (GitHub-style tables swallow it),
wrong cell counts, duplicate headings, and missing report links.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REQUIRED_HEADINGS = ("## What it has achieved so far", "## How the plant works", "## Follow along")
TABLE_HEADING = "## What it has achieved so far"
EXPECTED_COLUMNS = ("Target", "R1", "R2", "R3", "R4", "R5", "Evidence / boundary")


def split_cells(line: str) -> list[str]:
    """Split a GFM table row on unescaped pipes, ignoring pipes in code spans."""
    cells: list[str] = []
    buf: list[str] = []
    code = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            buf.append("|")
            i += 2
            continue
        if ch == "`":
            code = not code
            buf.append(ch)
            i += 1
            continue
        if ch == "|" and not code:
            cells.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    cells.append("".join(buf).strip())
    if cells and not cells[0]:
        cells = cells[1:]
    if cells and not cells[-1]:
        cells = cells[:-1]
    return cells


def main() -> int:
    problems: list[str] = []
    if not README.is_file():
        print("README.md is missing")
        return 2
    text = README.read_text(encoding="utf-8")
    lines = text.splitlines()
    for heading in REQUIRED_HEADINGS:
        count = lines.count(heading)
        if count != 1:
            problems.append(f"expected exactly one heading {heading!r}, found {count}")

    try:
        start = lines.index(TABLE_HEADING)
    except ValueError:
        print(f"missing table heading: {TABLE_HEADING}")
        return 2

    header = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("|")), None)
    if header is None:
        print("achievement table has no header")
        return 2
    delimiter = header + 1
    if delimiter >= len(lines) or not lines[delimiter].startswith("|"):
        problems.append(f"achievement table has no delimiter row at line {delimiter + 1}")
        header_cells: list[str] = []
        last_row = header
    else:
        header_cells = split_cells(lines[header])
        delimiter_cells = split_cells(lines[delimiter])
        if len(header_cells) != len(delimiter_cells):
            problems.append(
                f"table header has {len(header_cells)} cells but delimiter has {len(delimiter_cells)}")
        if len(header_cells) != len(EXPECTED_COLUMNS):
            problems.append(f"achievement header has {len(header_cells)} cells, expected {len(EXPECTED_COLUMNS)}")
        for column in EXPECTED_COLUMNS:
            if column not in header_cells:
                problems.append(f"achievement header missing column: {column}")
        if any(not re.fullmatch(r":?-{3,}:?", cell) for cell in delimiter_cells):
            problems.append("achievement delimiter row is not a Markdown separator")

        last_row = header
        idx = delimiter + 1
        while idx < len(lines) and lines[idx].startswith("|"):
            row_cells = split_cells(lines[idx])
            if len(row_cells) != len(header_cells):
                problems.append(
                    f"table row {idx + 1} has {len(row_cells)} cells, expected {len(header_cells)}")
            last_row = idx
            idx += 1

        # The exact bug seen in the README: prose immediately after the last
        # pipe row is swallowed into the GFM table. Require a blank boundary.
        if idx < len(lines) and lines[idx].strip():
            problems.append(
                f"achievement table needs a blank line after row {last_row + 1}; "
                f"line {idx + 1} would be parsed as a table row: {lines[idx][:60]!r}")
        if any(line.startswith("|") for line in lines[idx + 1:] if line.strip()):
            orphan = next(i + 1 for i in range(idx + 1, len(lines)) if lines[i].startswith("|"))
            problems.append(f"orphan table row after the achievement table at line {orphan}")

    row_count = max(0, last_row - delimiter)
    if row_count < 5:
        problems.append(f"achievement table has only {row_count} data rows")
    for match in re.finditer(r"\]\((reports/[^)]+)\)", text):
        if not (ROOT / match.group(1)).is_file():
            problems.append(f"report link is missing: {match.group(1)}")

    if problems:
        for problem in problems:
            print(f"README: {problem}")
        print(f"readme-lint: RED ({len(problems)} problems)")
        return 2
    print(f"readme-lint: GREEN ({row_count} achievement rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
