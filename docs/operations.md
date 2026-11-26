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

`research-manifest.json` is the single source for the front-page counts, the evidence-ladder graphic and the evidence register. Run `python3 tools/render-presentation.py` after editing it; the script rewrites `docs/results.md`, `docs/assets/evidence-ladder.svg` and the marked block in `README.md`. `python3 tools/check-readme.py .` lints the result.
