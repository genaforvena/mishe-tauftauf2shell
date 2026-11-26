#!/usr/bin/env python3
"""Render the public presentation from research-manifest.json.

Single source of truth for: the front-page overview block, the evidence ladder
graphic, and the evidence register. Run from anywhere:

    python3 tools/render-presentation.py [--check]

Without --check the three generated files are rewritten. With --check nothing
is written and a stale file exits 2. No network, no model, no dependencies.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent.parent
MANIFEST = ROOT / "research-manifest.json"
README = ROOT / "README.md"
RESULTS = ROOT / "docs" / "results.md"
SVG = ROOT / "docs" / "assets" / "evidence-ladder.svg"
BEGIN = "<!-- BEGIN GENERATED: research overview -->"
END = "<!-- END GENERATED: research overview -->"
STATUS_CELLS = (("✓", "Demonstrated"), ("◐", "Limited"), ("—", "Unestablished"))


def relinks(text: str) -> str:
    """Root-relative links become correct again once the text lives in docs/."""
    return re.sub(r"\]\((reports/|docs/|lab/)", r"](../\1", text)


def load() -> dict:
    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    findings = data["findings"]
    counts = data["counts"]
    if counts["reported_findings"]["value"] != len(findings):
        raise SystemExit("manifest: reported_findings does not match findings[]")
    if counts["active_research_minds"]["value"] != len({f["target"] for f in findings}):
        raise SystemExit("manifest: active_research_minds does not match distinct findings targets")
    established = sum(bool(f["established"]) for f in findings)
    if counts["independently_established_findings"]["value"] != established:
        raise SystemExit("manifest: independently_established_findings does not match findings[]")
    return data


def matrix(data: dict) -> dict[str, dict[str, int]]:
    out: dict[str, dict[str, int]] = {}
    for step in data["ladder"]:
        rung = step["rung"]
        out[rung] = {label: 0 for _, label in STATUS_CELLS}
        for finding in data["findings"]:
            cell = finding["rungs"][rung]
            label = dict(STATUS_CELLS).get(cell)
            if label is None:
                raise SystemExit(f"manifest: unknown cell {cell!r} in {finding['target']}")
            out[rung][label] += 1
    return out


def render_results(data: dict) -> str:
    counts = data["counts"]
    lines = [
        "# Evidence register",
        "",
        "Every reported finding, its rung cells and the exact boundary that was "
        "observed. Generated from [`research-manifest.json`](../research-manifest.json); "
        f"as of {data['as_of']}. The dated research log lives in "
        "[changelog.md](changelog.md).",
        "",
        f"- Declared research minds: **{counts['declared_research_minds']['value']}** "
        f"— {counts['declared_research_minds']['basis']}",
        f"- Active research minds: **{counts['active_research_minds']['value']}** "
        f"— {counts['active_research_minds']['basis']}",
        f"- Reported findings: **{counts['reported_findings']['value']}** "
        f"— {counts['reported_findings']['basis']}",
        f"- Independently established findings: "
        f"**{counts['independently_established_findings']['value']}** "
        f"— {counts['independently_established_findings']['basis']}",
        "",
        "Cells: `✓` demonstrated · `◐` limited (harness-only, instrumented or "
        "count-controlled) · `—` not demonstrated. Tiers: **LIVE** = real process on "
        "loopback with the request/wire path reached; **CODE** = verbatim pinned "
        "upstream or library bytes in-process; **HARNESS** = extracted or synthetic "
        "harness only. A witness marker means an independent replay was accepted at "
        "the scope named in that row; an author verdict never counts as acceptance. "
        "See [methodology.md](methodology.md) and "
        "[rce.md](rce.md) for the definitions and gates.",
        "",
        "## Evidence register",
        "",
        "| Target | R1 | R2 | R3 | R4 | R5 | Evidence / boundary |",
        "|---|---|---|---|---|---|---|",
    ]
    for finding in data["findings"]:
        rungs = finding["rungs"]
        lines.append(
            f"| **{finding['target']}** | {rungs['R1']} | {rungs['R2']} | {rungs['R3']} "
            f"| {rungs['R4']} | {rungs['R5']} | {relinks(finding['boundary'])} |"
        )
    return "\n".join(lines) + "\n"


def render_svg(data: dict) -> str:
    cells = matrix(data)
    n = len(data["findings"])
    x_cols = (500, 665, 830)
    colors = {"Demonstrated": "#3f6b50", "Limited": "#3e4348", "Unestablished": "#8b9295"}
    out = [
        '<svg xmlns="http://www.w3.org/2000/svg" width="980" height="472" viewBox="0 0 980 472" role="img" aria-label="Evidence ladder R1 to R5 by demonstrated, limited and unestablished cells">',
        '<rect width="980" height="472" fill="#fbfbf8"/>',
        '<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace">',
        '<text x="56" y="58" font-size="18" letter-spacing="2.5" fill="#2c3034">EVIDENCE LADDER / R1–R5</text>',
        '<text x="56" y="86" font-size="12" fill="#6b7376">Depth of proof, not boxes to tick.</text>',
        '<line x1="56" y1="112" x2="924" y2="112" stroke="#d7d9d4"/>',
    ]
    for x, (_, label) in zip(x_cols, STATUS_CELLS):
        out.append(
            f'<text x="{x}" y="146" font-size="11" letter-spacing="1.4" '
            f'text-anchor="middle" fill="{colors[label]}">{label.upper()}</text>'
        )
    y = 186
    for step in data["ladder"]:
        rung, label = step["rung"], step["label"]
        out.append(f'<text x="56" y="{y}" font-size="15" fill="#2c3034">{escape(rung)}</text>')
        out.append(f'<text x="112" y="{y}" font-size="13" fill="#3e4348">{escape(label)}</text>')
        for x, (_, status) in zip(x_cols, STATUS_CELLS):
            out.append(
                f'<text x="{x}" y="{y + 4}" font-size="17" text-anchor="middle" '
                f'fill="{colors[status]}">{cells[rung][status]}</text>'
            )
        out.append(f'<line x1="56" y1="{y + 18}" x2="924" y2="{y + 18}" stroke="#e7e8e3"/>')
        y += 56
    out.append(
        f'<text x="56" y="452" font-size="11" fill="#6b7376">'
        f'n = {n} findings · cells are rung states, not verdicts · '
        f'generated from research-manifest.json ({escape(data["as_of"])})</text>'
    )
    out.append("</g></svg>\n")
    return "\n".join(out)


def render_overview(data: dict) -> str:
    counts = data["counts"]
    cells = matrix(data)
    lines = [
        BEGIN,
        "Overview generated from [`research-manifest.json`](research-manifest.json) "
        f"({data['as_of']}):",
        "",
        "| Declared research minds | Active minds | Reported findings | Independently established |",
        "|---:|---:|---:|---:|",
        f"| {counts['declared_research_minds']['value']} | "
        f"{counts['active_research_minds']['value']} | "
        f"{counts['reported_findings']['value']} | "
        f"{counts['independently_established_findings']['value']} |",
        "",
        "Active means a target mind with at least one row in the register; "
        "engine-level activity is site state and is not claimed here. "
        "Independently established counts rows whose ESTABLISHED witness "
        "replay verdict was folded into the register's `established` flag at "
        "that verdict's exact scope; author-only verdicts and verdicts kept "
        "as boundary notes without a flag change are excluded.",
        "",
        "![Evidence ladder: rung cells by demonstrated, limited and unestablished "
        "status](docs/assets/evidence-ladder.svg)",
        "",
        "| Rung | Demonstrated | Limited | Unestablished |",
        "|---|---:|---:|---:|",
    ]
    for step in data["ladder"]:
        rung = step["rung"]
        row = cells[rung]
        lines.append(
            f"| {rung} {step['label']} | {row['Demonstrated']} | {row['Limited']} "
            f"| {row['Unestablished']} |"
        )
    lines += [
        "",
        "Full boundaries, scope notes and links are in the "
        "[evidence register](docs/results.md).",
        END,
    ]
    return "\n".join(lines)


def render_readme(data: dict) -> str:
    text = README.read_text(encoding="utf-8")
    start = text.find(BEGIN)
    end = text.find(END)
    if start < 0 or end < 0 or end < start:
        raise SystemExit(f"README.md is missing the generated block markers {BEGIN} / {END}")
    return text[:start] + render_overview(data) + text[end + len(END):]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify generated files are current")
    args = parser.parse_args()
    data = load()
    outputs = {
        RESULTS: render_results(data),
        SVG: render_svg(data),
        README: render_readme(data),
    }
    if args.check:
        stale = [str(path.relative_to(ROOT)) for path, text in outputs.items()
                 if not path.is_file() or path.read_text(encoding="utf-8") != text]
        if stale:
            print("presentation is stale: " + ", ".join(stale), file=sys.stderr)
            return 2
        print("presentation: GREEN (3 generated files current)")
        return 0
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    print("presentation: rendered README.md, docs/results.md, docs/assets/evidence-ladder.svg")
    return 0


if __name__ == "__main__":
    sys.exit(main())
