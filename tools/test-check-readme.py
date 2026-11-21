#!/usr/bin/env python3
"""Regression test for the README table-boundary lint.

The bug: a prose line immediately after the last pipe row is swallowed into
the GFM table. The linter must accept the shipped README and reject the same
README with that single blank boundary line removed.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINTER = ROOT / "tools" / "check-readme.py"
README = ROOT / "README.md"


def run(root: Path) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(LINTER), str(root)], capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def main() -> int:
    code, output = run(ROOT)
    if code != 0 or "GREEN" not in output:
        print(f"shipped README should lint GREEN: rc={code}\n{output}")
        return 1

    lines = README.read_text(encoding="utf-8").splitlines()
    heading = lines.index("## What it has achieved so far")
    last_row = next(i for i in range(heading + 1, len(lines)) if lines[i].startswith("|"))
    while last_row + 1 < len(lines) and lines[last_row + 1].startswith("|"):
        last_row += 1
    if last_row + 1 >= len(lines) or lines[last_row + 1].strip():
        print("fixture setup failed: shipped README has no blank boundary after the table")
        return 1
    broken = lines[:last_row + 1] + lines[last_row + 2:]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "README.md").write_text("\n".join(broken) + "\n", encoding="utf-8")
        (root / "reports").symlink_to(ROOT / "reports", target_is_directory=True)
        code, output = run(root)
    if code != 2 or "blank line after row" not in output:
        print(f"broken boundary should lint RED: rc={code}\n{output}")
        return 1
    print("readme-lint regression: PASS (GREEN shipped, RED boundary removed)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
