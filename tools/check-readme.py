#!/usr/bin/env python3
"""Lint the front page and the generated evidence register.

Exit 0 GREEN, 2 RED. System 0 check: no model, no repair, exact rules.
The overview lives in README.md; the seven-column achievement table lives in
docs/results.md and is generated from research-manifest.json. The lint parses
the table as a contiguous block and catches orphan rows, a blank-boundary
regression, a prose line swallowed into the table, wrong cell counts, missing
headings/generated markers, broken relative links and a stale manifest count.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parent.parent
README = ROOT / "README.md"
RESULTS = ROOT / "docs" / "results.md"
MANIFEST = ROOT / "research-manifest.json"
REQUIRED_HEADINGS = ("## The evidence ladder", "## How the plant works", "## Research archive")
TABLE_HEADING = "## Evidence register"
GENERATED_MARKERS = (
    "<!-- BEGIN GENERATED: research overview -->",
    "<!-- END GENERATED: research overview -->",
)
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


def check_links(path: Path, text: str, problems: list[str]) -> None:
    for match in re.finditer(r"\]\(([^)]+)\)", text):
        target = match.group(1)
        if target.startswith(("http://", "https://", "mailto:", "#")) or "#" in target:
            continue
        target_path = path.parent / target
        if target_path.is_file() or target_path.is_dir():
            continue
        problems.append(f"{path.relative_to(ROOT)}: link is missing: {target}")


def main() -> int:
    problems: list[str] = []
    for path in (README, RESULTS):
        if not path.is_file():
            print(f"{path.relative_to(ROOT)} is missing")
            return 2
    readme_text = README.read_text(encoding="utf-8")
    results_text = RESULTS.read_text(encoding="utf-8")
    lines = results_text.splitlines()

    for heading in REQUIRED_HEADINGS:
        count = readme_text.splitlines().count(heading)
        if count != 1:
            problems.append(f"expected exactly one front-page heading {heading!r}, found {count}")
    for marker in GENERATED_MARKERS:
        if readme_text.count(marker) != 1:
            problems.append(f"expected exactly one generated marker {marker!r}")
    if readme_text.count(GENERATED_MARKERS[0]) == 1 and readme_text.count(GENERATED_MARKERS[1]) == 1:
        if readme_text.index(GENERATED_MARKERS[0]) > readme_text.index(GENERATED_MARKERS[1]):
            problems.append("generated markers are out of order")

    if lines.count(TABLE_HEADING) != 1:
        print(f"missing table heading: {TABLE_HEADING}")
        return 2
    start = lines.index(TABLE_HEADING)
    header = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("|")), None)
    if header is None:
        print("achievement table has no header")
        return 2
    delimiter = header + 1
    if delimiter >= len(lines) or not lines[delimiter].startswith("|"):
        problems.append(f"achievement table has no delimiter row at line {delimiter + 1}")
        header_cells: list[str] = []
        last_row = header
        targets: list[str] = []
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
        targets = []
        idx = delimiter + 1
        while idx < len(lines) and lines[idx].startswith("|"):
            row_cells = split_cells(lines[idx])
            if len(row_cells) != len(header_cells):
                problems.append(
                    f"table row {idx + 1} has {len(row_cells)} cells, expected {len(header_cells)}")
            else:
                targets.append(row_cells[0].replace("*", "").strip())
            last_row = idx
            idx += 1

        # The exact bug seen in the old README: prose immediately after the
        # last pipe row is swallowed into the GFM table. Require a blank
        # boundary; a generated file ends with a newline after that boundary.
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

    check_links(README, readme_text, problems)
    check_links(RESULTS, results_text, problems)

    if MANIFEST.is_file():
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        declared = data["counts"]["reported_findings"]["value"]
        if declared != row_count:
            problems.append(f"manifest reports {declared} findings, register has {row_count} rows")
        if [f["target"] for f in data["findings"]] != targets:
            problems.append("manifest findings[] does not match the register row order")

    if problems:
        for problem in problems:
            print(f"presentation: {problem}")
        print(f"readme-lint: RED ({len(problems)} problems)")
        return 2
    print(f"readme-lint: GREEN ({row_count} achievement rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
