#!/usr/bin/env python3
"""Hard plant-scoped engine guard: only engine=omp and model=hy4-flash-free.

Exit 2 with exact offenders if any declared role, route, engine config, or
generated wake unit can select claude, codex, qwen or any other engine/model.
Exit 0 with the count of checked roles when the plant is clean. This is a
System 0 guard; it calls no model and never repairs anything.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ALLOWED_ENGINE = "omp"
ALLOWED_MODEL = "opencode-go/hy4-flash-free"


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: check-omp-only.py SITE_HOME CHECKOUT")
        return 2
    home, repo = Path(sys.argv[1]).resolve(), Path(sys.argv[2]).resolve()
    release = home / "runtime" / "current" / "src"
    sys.path.insert(0, str(release))
    from mishe_tauftauf.roles import declared  # type: ignore

    problems: list[str] = []
    roles = sorted(declared(home))
    routes = json.loads((home / "engine" / "routes.json").read_text(encoding="utf-8"))
    routed = routes.get("roles", {})
    for role in roles:
        candidates = routed.get(role)
        if not candidates:
            problems.append(f"{role}: no route (legacy fallback can select claude/codex)")
            continue
        for candidate in candidates:
            if candidate.get("engine") != ALLOWED_ENGINE or candidate.get("model") != ALLOWED_MODEL:
                problems.append(f"{role}: forbidden candidate {candidate.get('engine')}/{candidate.get('model')}")
    for role in sorted(set(routed) - set(roles)):
        problems.append(f"{role}: stale route for undeclared role")
    for path in sorted((home / "engines").glob("*.json")) if (home / "engines").is_dir() else []:
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("engine") != ALLOWED_ENGINE or data.get("model", ALLOWED_MODEL) != ALLOWED_MODEL:
            problems.append(f"legacy engine file {path.name}: forbidden {data}")

    # Generated unit text is evidence, not authority, but a stale Claude unit is
    # still dangerous if the generated file is ever run directly.
    unit_dir = Path.home() / ".config" / "systemd" / "user"
    for path in sorted(unit_dir.glob("m2shell-wake@*.service")):
        text = path.read_text(encoding="utf-8")
        if re.search(r"engine[-_](claude|codex)|claude-haiku|codex", text, re.IGNORECASE):
            problems.append(f"generated unit names a forbidden engine: {path.name}")
    for problem in problems:
        print(f"omp-only: {problem}")
    print(f"omp-only: {'RED' if problems else 'GREEN'} ({len(roles)} declared roles)")
    return 2 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
