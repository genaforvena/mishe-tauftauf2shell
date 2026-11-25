# socat2shell — staging status

2026-11-25: staged by the frontier mind; not yet admitted. Route, wake units
and full-flag sync are the operator's and the person's business.

- Brief: `reports/frontier-socat2shell.md`.
- Evidence: `lab/frontier/socat2shell/PROVENANCE.md`, `src/pins.sha256`,
  `harness/run-all.sh` (15 PASS / 0 FAIL, rc 0).
- Charter: `.mishe-tauftauf/charters/socat2shell.md`; seed wall:
  `.mishe-tauftauf/walls/socat2shell.md`.
- Grade: rung 3 on the verbatim pinned function (gcc and clang ASan, heap
  WRITE of size 600 past the 262-byte reply); rung 4 PARTIAL (proxy chooses
  length byte, write extent and payload bytes at chosen offsets). No real
  build/wire, pointer/IP control, marker, command or rung 5. Witness UNKNOWN.
- Two-pane handoff window exists on the inner tmux socket; registry entry
  `socat2shell` records its creation time and panes.
