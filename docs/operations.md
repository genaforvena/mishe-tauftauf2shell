# Operations

Internal pointers for dashboards, ground-truth documents and the laboratory. Preserved from the former README "Follow along" section.

## Follow along

- Live dashboards:
  `tmux -S /tmp/tmux-1000/mishe-tauftauf2shell/tmux-1000/default attach -t mishe-tauftauf2shell-current`
  — one window per target mind above, plus `frontier`, `docs`, `witness`,
  `operator`, `chat`, `git` and `wakes`.
- [docs/task.md](../docs/task.md) — verified ground truth for each CVE, the
  staged plan and the rules of the lab.
- [docs/reproducibility.md](../docs/reproducibility.md) — pins, commands,
  expected bytes and evidence policy for independent verification.
- [docs/rce.md](../docs/rce.md) — the rung-5 acceptance contract and first lane.
- [docs/runtime-pin.md](../docs/runtime-pin.md) — the pinned runtime and every
  local change made to it.
- [docs/self-healing.md](../docs/self-healing.md) — duties, signals and the
  no-force publication/reconciliation design.
- `reports/` — the investigation reports and live status files; `lab/` — the
  builds and harnesses.


## Presentation maintenance

`research-manifest.json` is the single source for the front-page counts, the evidence-ladder graphic and the evidence register. `python3 tools/render-presentation.py` rewrites `README.md`, `docs/results.md` and `docs/assets/evidence-ladder.svg`; `python3 tools/render-presentation.py --check` verifies all three are current. `python3 tools/check-readme.py .` lints the result and goes RED when any generated file is stale.

The checkout installs a pre-commit hook for the automatic path: `sh tools/install-pre-commit-presentation.sh` links `tools/pre-commit-presentation.sh` into `.git/hooks/pre-commit`. Whenever a commit stages `research-manifest.json`, the hook re-renders and stages all three generated files, so the published front page cannot lag the manifest. The hook refuses to replace a pre-commit hook it did not install. On a fresh checkout, run the installer once; the post-commit push hook is installed separately by `tools/install-post-commit-push.sh`.
