#!/usr/bin/env python3
"""Check that the committed reproducibility spine exists and is documented.

Exit 0 when every required first-party harness, provisioning script and report
is tracked and the README links the index; 2 when a named requirement is
missing. Raw logs, source trees and builds are intentionally not checked.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REQUIRED = [
    "README.md", "docs/reproducibility.md", "docs/task.md", "docs/runtime-pin.md",
    "lab/node2shell/provision.sh", "lab/ruby2shell/provision.sh",
    "lab/php2shell/provision.sh", "lab/php2shell/build.sh", "lab/php2shell/build-fpm.sh",
    "lab/php2shell/build-apache.sh", "lab/preload/build-mtrace.sh",
    "lab/frontier/mosquitto2shell/provision.sh", "lab/frontier/mosquitto2shell/provision-cjson.sh",
    "lab/frontier/brotli2shell/run.sh", "lab/frontier/postgres2shell/run.sh",
    "lab/frontier/dragonfly2shell/run.sh",
    "lab/repro/node2shell-sourcepins/fix-ae9ab37d62.diff",
    "lab/repro/ruby2shell-stageC-variant.rb",
    "lab/witness/dragonfly2shell/w11-gdb.cmd",
    "lab/witness/dragonfly2shell/witness_probe.py",
    "reports/ruby2shell-investigation.md", "reports/php2shell-investigation.md",
    "reports/node2shell-investigation.md", "reports/apache2shell-investigation.md",
    "reports/frontier-mosquitto2shell.md", "reports/mosquitto2shell-status.md",
    "reports/frontier-brotli2shell.md", "reports/frontier-postgres2shell.md",
    "reports/frontier-dragonfly2shell.md",
]
HASH_MARKERS = {
    "lab/node2shell/provision.sh": "48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75",
    "lab/ruby2shell/provision.sh": "db6c147940d7ad0b706823d42c8e6713c36dec70a1f83f635f1d3a7f0599ec90",
    "lab/frontier/mosquitto2shell/provision-cjson.sh": "c91d1eeb7175c50d49f6ba2a25e69b46bd05cffb798382c19bfb202e467ec51c",
    "lab/frontier/brotli2shell/run.sh": "3f6d79b00daf87e0ff69914ef25dc3331afd5ef319b261bd8fdc2403a24a3d9d",
    "lab/frontier/postgres2shell/run.sh": "sha256:ff87138949ad9a46f32ff23bd6852b52ce024a13dffe9b4087be98292cdd3b4f",
    "lab/frontier/dragonfly2shell/run.sh": "sha256:ebf3c6c213e82fb51b4521660cca13f06f3421dc5b1ed14f2f474c50b5e29986",
}


def main() -> int:
    tracked = set(subprocess.check_output(["git", "-C", str(ROOT), "ls-files"], text=True).splitlines())
    problems = []
    for rel in REQUIRED:
        if rel not in tracked:
            problems.append(f"not tracked: {rel}")
        elif not (ROOT / rel).is_file():
            problems.append(f"tracked but missing on disk: {rel}")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if "(docs/reproducibility.md)" not in readme:
        problems.append("README does not link docs/reproducibility.md")
    for rel, marker in HASH_MARKERS.items():
        if rel in tracked and marker not in (ROOT / rel).read_text(encoding="utf-8"):
            problems.append(f"missing pinned hash in {rel}")
    for problem in problems:
        print(problem)
    print(f"reproducibility: {'FAIL' if problems else 'GREEN'} ({len(REQUIRED)} required files)")
    return 2 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
