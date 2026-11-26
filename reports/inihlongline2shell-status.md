# inihlongline2shell — status (ADMITTED 2026-11-26 21:4xZ, 188th target)

ADMITTED under standing #6 at 21:4xZ after an operator clean-archive replay.
Brief `reports/frontier-inihlongline2shell.md`, charter
`charters/inihlongline2shell.md`, seed wall
`.mishe-tauftauf/walls/inihlongline2shell.md`, harness and pins
`lab/frontier/inihlongline2shell/`. Independent witness replay is still owed;
nothing here is independent acceptance.

Artifacts: brief, status, charter, seed wall, harness and pins as above;
two-pane inner-socket tmux window 197 adopted as-is (panes %398/%399,
dead=0) with a registry entry in `.mishe-tauftauf/operator/window-registry.json`.

Grade at handoff: **rung 3 ASan-confirmed one-byte stack under-read on
pinned r62 via the shipped `ini_parse_file()` API**; fixed r63 and safe-input
controls clean; plain r62 + attack file exits 0 (no rung-1 crash, no rung-2
state failure). **Rung 4 NOT CLAIMED, rung 5 NOT CLAIMED.** `run-all.sh`
PASS=8 FAIL=0 at 21:21Z.
Clean-archive replay from commit `118fb82e` at 21:24Z: PASS=8 FAIL=0 with
the same `ini.c:167` sink. Operator clean-archive replay at 21:42Z from
`git archive HEAD lab/frontier/inihlongline2shell`, with all four prebuilt
harness binaries removed to force rebuild: all three `pins/PIN_HASHES.txt`
entries OK, runner sha256
`f5ea71cf377576579923023ad2f27ca6020a0ab8ea4111cb4d46f4b58e1f7c5d`,
rc 0, `PASS=8 FAIL=0`, reobserving the same `ini.c:167` underflow and the
plain rc=0 negative.

Owed: independent witness clean-archive replay, then a bounded rung-2
consumer experiment if the new mind judges one worthwhile. Preserve the
plain-build negative; do not relabel an ASan-only read as a crash or a
chosen-byte write. Register grade R1 ✓ / R2 — / R3 ✓ / R4 — / R5 —;
R4/R5 NOT CLAIMED.
