#!/usr/bin/env python3
"""Regression tests for the split presentation lint.

The old bug: a prose line immediately after the last pipe row is swallowed
into the GFM table. The linter must accept the shipped layout and reject the
same register with that blank boundary removed. It must also reject a register
that disagrees with the manifest count.
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LINTER = ROOT / "tools" / "check-readme.py"
README = ROOT / "README.md"
RESULTS = ROOT / "docs" / "results.md"
LINKED = (
    "docs/methodology.md", "docs/architecture.md", "docs/changelog.md",
    "docs/operations.md", "docs/reproducibility.md", "docs/rce.md",
    "docs/assets/evidence-ladder.svg", "reports", "LICENSE",
)


def run(root: Path) -> tuple[int, str]:
    result = subprocess.run(
        [sys.executable, str(LINTER), str(root)], capture_output=True, text=True, check=False)
    return result.returncode, result.stdout + result.stderr


def fixture(root: Path, results_text: str, manifest_text: str | None = None,
            readme_text: str | None = None) -> None:
    (root / "README.md").write_text(readme_text or README.read_text(encoding="utf-8"), encoding="utf-8")
    (root / "docs").mkdir(exist_ok=True)
    (root / "docs" / "results.md").write_text(results_text, encoding="utf-8")
    for rel in LINKED:
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.symlink_to(ROOT / rel, target_is_directory=rel == "reports")
    if manifest_text is None:
        (root / "research-manifest.json").symlink_to(ROOT / "research-manifest.json")
    else:
        (root / "research-manifest.json").write_text(manifest_text, encoding="utf-8")


def main() -> int:
    code, output = run(ROOT)
    if code != 0 or "GREEN" not in output:
        print(f"shipped presentation should lint GREEN: rc={code}\n{output}")
        return 1

    original = RESULTS.read_text(encoding="utf-8")
    lines = original.splitlines()
    last_row = max(i for i, line in enumerate(lines) if line.startswith("|"))
    broken = "\n".join(lines[:last_row + 1] + ["prose swallowed into the table", ""]) + "\n"
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture(root, broken)
        code, output = run(root)
    if code != 2 or "blank line after row" not in output:
        print(f"broken boundary should lint RED: rc={code}\n{output}")
        return 1

    data = json.loads((ROOT / "research-manifest.json").read_text(encoding="utf-8"))
    data["counts"]["reported_findings"]["value"] += 1
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture(root, original, json.dumps(data))
        code, output = run(root)
    if code != 2 or "manifest reports" not in output:
        print(f"stale manifest count should lint RED: rc={code}\n{output}")
        return 1

    shipped = json.loads((ROOT / "research-manifest.json").read_text(encoding="utf-8"))
    readme = README.read_text(encoding="utf-8")
    begin = readme.index("<!-- BEGIN GENERATED: research overview -->")
    end = readme.index("<!-- END GENERATED: research overview -->")
    stale = readme[:begin] + readme[begin:end].replace(shipped["as_of"], "2000-01-01", 1) + readme[end:]
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        fixture(root, original, readme_text=stale)
        code, output = run(root)
    if code != 2 or "generated overview is stale" not in output:
        print(f"stale overview should lint RED: rc={code}\n{output}")
        return 1

    print("readme-lint regression: PASS (GREEN shipped, RED boundary, stale count and overview)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
