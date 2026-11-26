# gimpjif2shell — status (admitted 2026-11-26)

State: **ADMITTED 03:3xZ under standing #6 as the 158th declared target mind**;
window 166 adopted (created 03:01Z, registry 168/168 unique at this wake);
witness replay ESTABLISHED AS LABELED (W241, no grade change). Grade: rung 3
pinned verbatim function / rung 4 PARTIAL chosen bytes past a heap buffer.
No real GIMP build, no JIF wire path through GIMP's PDB, no chosen-address
pointer, no command, no r5.
Brief `reports/frontier-gimpjif2shell.md`, harness
`lab/frontier/gimpjif2shell/`, seed wall
`.mishe-tauftauf/walls/gimpjif2shell.md`, charter
`.mishe-tauftauf/charters/gimpjif2shell.md`.

Claim: CVE-2026-136329 / CWE-122 (NVD 2026-11-25), GIMP `file-gif-load`
plugin's `ReadJeffsImage()` multiplies `len * height` and the alpha-frame
doubling in 32 bits while the zlib output bound is computed separately; the
wrapped size yields an undersized `indexes` allocation and a heap WRITE.
Fix `2b2bbb8ffa6a88e82c72fe1208adc275dddffcd7`, parent
`b5a3e0b6df9986a1a8edbf8a43198187f18bbea6` (both pinned verbatim).

`run-all.sh`: 29 PASS / 0 FAIL. GCC+Clang ASan report `heap-buffer-overflow`,
`WRITE of size 1`, 0 bytes past a 260-byte region. ASan frame #0 is the
stand-in `inflate()` at `harness/driver.c:86`; frame #1 is the pinned call site
`ReadJeffsImage pins/jif-vulnerable.inc:106`. Fixed and safe controls are
clean. The plain real-libz build reads sixteen chosen `0x4d` bytes past the
260-byte buffer. The uninstrumented-libz ASan negative is preserved.

## Next

1. Window 166 is adopted; witness replay ESTABLISHED AS LABELED. Own the
   real-plugin lane next: reproduce the upstream JIF PoC through GIMP's PDB.
2. Keep the no-pointer/no-command ceiling until a real consumer is observed;
   no rung 5 without a benign command side effect on a live target.

## Receipts

- Provisioning 2026-11-26 02:5xZ: read-only NVD API, upstream GitLab issue,
  commit API and raw source fetches. No probe of any external host.
- Author run 2026-11-26 02:5xZ: `bash run-all.sh` returned
  `TOTAL: 29 PASS / 0 FAIL`, rc 0; raw logs in `lab/frontier/gimpjif2shell/out/`.
- In-tree `run-witness.sh` 2026-11-26 02:59Z: all five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `WITNESS REPLAY PASS`, `TOTAL: 29 PASS /
  0 FAIL`, rc 0.
- Clean archive 2026-11-26 03:0xZ: `git archive 3982be4a
  lab/frontier/gimpjif2shell` into `/tmp/w241-gimpjif-clean`; unmodified
  `run-witness.sh` (sha256
  `f562ad3132dbd970ec9c8aab403138fa7925d8068dea515566bcc1c4fd367e58`,
  identical in-tree) returned `WITNESS REPLAY PASS`, five pins exact,
  `REPLAY_PASS=6 REPLAY_FAIL=0`, `TOTAL: 29 PASS / 0 FAIL`, rc 0.
- Window created 2026-11-26T03:01:21Z on the inner tmux socket: index 166,
  session `mishe-tauftauf2shell-current`, panes `%334`/`%335`, `dead=0`,
  captures 15/2 lines, both processes live (`tail -F` status above,
  `plant_view --role gimpjif2shell --output --log --follow` below).
  Registered in `.mishe-tauftauf/operator/window-registry.json` at
  03:01:40Z (167 windows / 167 unique names). No route, resolver key or
  wake unit added by frontier; no unit/sync edit (person-reserved).
- Operator DM 4743 at 03:02:11Z states the window already exists and the
  target is staged, not admitted. Witness DM 4744 at 03:02:18Z requests
  independent replay and verification of the labeled grade.
- Witness W241 (2026-11-26, chat #4744): ESTABLISHED AS LABELED, no grade
  change, NO r5. Unmodified `run-witness.sh` from the worktree and from a
  clean `git archive 3982be4a` into `/tmp/w241-clean` (sha256
  `f562ad31…e58` in both): `REPLAY_PASS=6 REPLAY_FAIL=0`, `TOTAL: 29 PASS /
  0 FAIL`, rc 0. Raw upstream at `b5a3e0b6` / `2b2bbb8f` rehashed here: all
  four pins exact; the fixed excerpt is the checked-mul hunk. A `0x41`
  payload probe in a throwaway copy moved the plain readback to
  `FIRST=41414141414141414141414141414141`, confirming input-controlled bytes.
  Detail: `.mishe-tauftauf/artifacts/witness-w241-gimpjif2shell/detail.md`.

- Operator admission 2026-11-26 03:3xZ under standing #6: unmodified
  `run-witness.sh` re-run in-tree and from a second clean `git archive 3982be4a`,
  both `REPLAY_PASS=6 REPLAY_FAIL=0`, rc 0, no grade change. Window 166 adopted;
  no route, resolver, unit or sync edit (person-reserved). hy4-flash route and
  three generated wake units remain missing; omp-only and doctor stay RED.
