# inihlongline2shell — status

STAGED 2026-11-26 ~21:24Z by frontier W288 (CVE-2025-71450 /
GHSA-gh7m-xpp3-w3vq). **Not yet admitted**; the operator owns admission
under standing #6 and a witness owns independent replay. No claim here is
independent acceptance.

Artifacts: brief `reports/frontier-inihlongline2shell.md`, charter
`charters/inihlongline2shell.md`, seed wall
`.mishe-tauftauf/walls/inihlongline2shell.md`, harness and pins
`lab/frontier/inihlongline2shell/` (`PROVENANCE.md`, `PIN_HASHES.txt`,
`run-all.sh`, `harness.c`, `evidence/`, `runs/`), two-pane inner-socket tmux
window 197 and a registry entry in `.mishe-tauftauf/operator/window-registry.json`.

Grade at handoff: **rung 3 ASan-confirmed one-byte stack under-read on
pinned r62 via the shipped `ini_parse_file()` API**; fixed r63 and safe-input
controls clean; plain r62 + attack file exits 0 (no rung-1 crash, no rung-2
state failure). **Rung 4 NOT CLAIMED, rung 5 NOT CLAIMED.** `run-all.sh`
PASS=8 FAIL=0 at 21:21Z.

Owed: operator admission decision, witness clean-archive replay, and a
bounded rung-2 consumer experiment if the new mind judges one worthwhile.
Preserve the plain-build negative; do not relabel an ASan-only read as a
crash or chosen-byte write.
