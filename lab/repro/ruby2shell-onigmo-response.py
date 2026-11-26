#!/usr/bin/env python3
"""Compare stock /rails/info/notes HTML for Onigmo corruption.

Usage: ruby2shell-onigmo-response.py CONTROL.html ATTACK.html [--json OUT]
Exit 0 when the attack changes or removes reflected source rows, 1 when clean.
"""
from __future__ import annotations

import argparse
import html
import json
from pathlib import Path
import re
import sys

FILE_BLOCK = re.compile(
    r'<th rowspan="\d+">\s*(.*?)\s*</th>(.*?)(?=<th rowspan="\d+">|</tbody>)',
    re.S,
)
ROW = re.compile(
    r'<td class="line-no">(\d+)</td>\s*<td class="tag">(.*?)</td>\s*<td>(.*?)</td>',
    re.S,
)


def clean(fragment: str) -> str:
    return html.unescape(re.sub(r"<.*?>", "", fragment))


def rows(path: Path) -> dict[tuple[str, int], tuple[str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    result: dict[tuple[str, int], tuple[str, str]] = {}
    for block in FILE_BLOCK.finditer(text):
        filename = clean(block.group(1)).strip()
        for row in ROW.finditer(block.group(2)):
            result[(filename, int(row.group(1)))] = (clean(row.group(2)), clean(row.group(3)))
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("control", type=Path)
    parser.add_argument("attack", type=Path)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()
    control = rows(args.control)
    attack = rows(args.attack)
    missing = sorted(set(control) - set(attack))
    added = sorted(set(attack) - set(control))
    changed = [
        {
            "file": key[0],
            "line": key[1],
            "control": control[key],
            "attack": attack[key],
        }
        for key in sorted(set(control) & set(attack))
        if control[key] != attack[key]
    ]
    shortened = [
        item for item in changed
        if len(item["attack"][1]) == len(item["control"][1]) - 1
    ]
    report = {
        "control": str(args.control),
        "attack": str(args.attack),
        "control_rows": len(control),
        "attack_rows": len(attack),
        "missing": missing,
        "added": added,
        "changed": changed,
        "shortened_by_one": len(shortened),
        "verdict": "CORRUPTED" if missing or added or changed else "CLEAN",
    }
    if args.json:
        args.json.write_text(json.dumps(report, indent=2) + "\n")
    print(
        f"control_rows={len(control)} attack_rows={len(attack)} "
        f"missing={len(missing)} added={len(added)} changed={len(changed)} "
        f"shortened_by_one={len(shortened)} verdict={report['verdict']}"
    )
    for item in changed[:10]:
        print(
            f"CHANGE {item['file']}:{item['line']} "
            f"{item['control'][1]!r} -> {item['attack'][1]!r}"
        )
    for filename, line in missing[:10]:
        print(f"MISSING {filename}:{line} {control[(filename, line)][1]!r}")
    return 0 if report["verdict"] == "CORRUPTED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
