#!/usr/bin/env python3
"""Regression test for the presentation pre-commit hook and its installer.

The hook must re-render and stage README.md, docs/results.md and the ladder SVG
whenever a commit stages research-manifest.json, and stay inert otherwise. The
installer must not clobber a hook it did not install.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "tools" / "pre-commit-presentation.sh"
INSTALLER = ROOT / "tools" / "install-pre-commit-presentation.sh"
GENERATED = ("README.md", "docs/results.md", "docs/assets/evidence-ladder.svg")


def git(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True)


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        for rel in (*GENERATED, "research-manifest.json", "tools/render-presentation.py",
                    HOOK.relative_to(ROOT), INSTALLER.relative_to(ROOT)):
            target = repo / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / rel, target)

        for args in (("init", "-q"), ("config", "user.email", "test@example.invalid"),
                     ("config", "user.name", "test"), ("add", "-A"),
                     ("commit", "-q", "-m", "base")):
            result = git(repo, *args)
            if result.returncode != 0:
                print(f"git {' '.join(args)} failed: {result.stderr}")
                return 1

        installer = repo / INSTALLER.relative_to(ROOT)
        installed = subprocess.run(["sh", str(installer)], cwd=repo, capture_output=True, text=True)
        if installed.returncode != 0:
            print(f"installer failed: {installed.stdout}{installed.stderr}")
            return 1

        hook = repo / ".git" / "hooks" / "pre-commit"
        if not hook.is_symlink() or hook.resolve() != (repo / HOOK.relative_to(ROOT)).resolve():
            print("installer did not link the hook")
            return 1

        # No staged manifest: the hook is inert and must not rewrite the front page.
        before = (repo / "README.md").read_text(encoding="utf-8")
        inert = subprocess.run(["sh", str(repo / HOOK.relative_to(ROOT))], cwd=repo,
                               capture_output=True, text=True)
        if inert.returncode != 0 or (repo / "README.md").read_text(encoding="utf-8") != before:
            print("hook should be inert without a staged manifest")
            return 1

        manifest_path = repo / "research-manifest.json"
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        data["as_of"] = "2001-02-03"
        manifest_path.write_text(json.dumps(data), encoding="utf-8")
        if git(repo, "add", "--", "research-manifest.json").returncode != 0:
            print("cannot stage the manifest")
            return 1
        committed = git(repo, "commit", "-q", "-m", "manifest bump")
        if committed.returncode != 0:
            print(f"commit with hook failed: {committed.stderr}")
            return 1

        for rel in GENERATED:
            if "2001-02-03" not in (repo / rel).read_text(encoding="utf-8"):
                print(f"{rel} was not re-rendered from the staged manifest")
                return 1
        names = git(repo, "show", "--format=", "--name-only", "HEAD").stdout.splitlines()
        if not all(rel in names for rel in GENERATED):
            print(f"generated files missing from the commit: {names}")
            return 1

        # A foreign pre-commit hook must not be replaced.
        hook.unlink()
        hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        refused = subprocess.run(["sh", str(installer)], cwd=repo, capture_output=True, text=True)
        if refused.returncode == 0 or "refusing" not in refused.stderr:
            print("installer should refuse a foreign hook")
            return 1
        if hook.read_text(encoding="utf-8") != "#!/bin/sh\nexit 0\n":
            print("installer rewrote a foreign hook")
            return 1

    print("pre-commit presentation regression: PASS (render, stage, inert, refusal)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
