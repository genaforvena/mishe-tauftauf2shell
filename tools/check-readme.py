#!/usr/bin/env python3
"""Lint README.md structure and the achievement table.

Exit 0 GREEN, 2 RED. This is a System 0 check: no model, no fix, exact rules.
It catches the failure mode where a table row is orphaned by a blank line,
a row has the wrong number of cells, a report link is missing, or a heading
structure is broken. The docs mind owns repairs.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
REQUIRED_HEADINGS = ("## What it has achieved so far", "## How the plant works", "## Follow along")
TABLE_HEADING = "## What it has achieved so far"
EXPECTED_COLUMNS = ("Target", "Where it stands", "Highlights")

def cells(line: str) -> int:
    """Count Markdown table cells, ignoring pipes escaped with a backslash."""
    return len(re.findall(r"(?<!\\)\|", line)) - 1


def main() -> int:
    problems: list[str] = []
    if not README.is_file():
        print("README.md is missing")
        return 2
    text = README.read_text(encoding="utf-8")
    lines = text.splitlines()
    for heading in REQUIRED_HEADINGS:
        if lines.count(heading) != 1:
            problems.append(f"expected exactly one heading: {heading}")

    try:
        start = lines.index(TABLE_HEADING)
    except ValueError:
        print(f"missing table heading: {TABLE_HEADING}")
        return 2

    # Find the first table after the achievement heading.
    header = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("|")), None)
    if header is None:
        print("achievement table has no header")
        return 2
    delimiter = header + 1
    if delimiter >= len(lines) or not lines[delimiter].startswith("|"):
        problems.append("achievement table has no delimiter row")
    else:
        if cells(lines[header]) != cells(lines[delimiter]):
            problems.append("achievement table header and delimiter have different column counts")
        for column in EXPECTED_COLUMNS:
            if column not in lines[header]:
                problems.append(f"achievement header missing column: {column}")

    # Walk the whole table. A blank line followed by another pipe row is the
    # exact bug this lint exists to catch. A non-pipe line ends the table.
    in_table = False
    ended = False
    previous_blank = False
    row_count = 0
    expected = cells(lines[header])
    for index in range(header, len(lines)):
        line = lines[index]
        number = index + 1
        if line.startswith("|"):
            if ended:
                problems.append(f"orphan table row after blank line at {number}")
            elif previous_blank:
                problems.append(f"blank line splits achievement table at {number}")
            if cells(line) != expected:
                problems.append(f"table row {number} has {cells(line)} cells, expected {expected}")
            in_table = True
            previous_blank = False
            if index > delimiter:
                row_count += 1
        elif in_table and not line.strip():
            previous_blank = True
        elif in_table:
            in_table = False
            ended = True
            previous_blank = False

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
