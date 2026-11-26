# ettercapgg2shell — STAGED, WINDOW 177 LIVE (2026-11-26)

Brief: `reports/frontier-ettercapgg2shell.md`. Lab:
`lab/frontier/ettercapgg2shell/`. Claim: CVE-2026-125401 /
GHSA-vrjv-f8gv-2h35, ettercap `<= 0.8.4.1` before `0.8.5.1` lets an
attacker-controlled `u_int32 version` compose up to 44 bytes into a 30-byte
heap buffer in `gg_get_version()` (`src/dissectors/ec_gg.c`). Fixed by the
bounded `snprintf` helper in PR #1330 and the `v0.8.5.1` tag. State: **STAGED
by frontier; witness replay closed in W261, operator admission owed**.
Window 177 `ettercapgg2shell` created on the inner tmux socket
(`mishe-tauftauf2shell-current`), panes %356/%357, both live (top: this
status, bottom: `plant_view --role ettercapgg2shell --output --log --follow`);
registered in `operator/window-registry.json`. No duplicate window is needed.

Evidence: canonical `run-all.sh` sha256
`35c3f7d532a62b107f806d7b126e4f76bead860d949ce7b57217e22f458958c4` verifies
pinned archives, fix patch, driver and both verbatim function bodies; it
rebuilds both tags under GCC+Clang ASan and GCC+Clang plain. **RESULT
PASS=25 FAIL=0**, rc 0: vulnerable ASan `WRITE of size 13`, 0 bytes after the
30-byte region, at verbatim `src/dissectors/ec_gg.c:673` on both compilers;
fixed runs truncate to 29 chars with no ASan; safe inputs clean. Plain
vulnerable builds show chosen hex digit `0x34` at offset 11 (in bounds) and
suffix bytes `0x69`/`0x78` at offsets 30/42 (past the allocation). Grade:
rung 3 verbatim / rung 4 PARTIAL — attacker controls overflow length, not the
overflowing bytes; no named adjacent object, pointer, wire path, command or
r5. Negatives are preserved in `lab/frontier/ettercapgg2shell/PROVENANCE.md`.

Author clean-archive replay of the unmodified runner from `git archive
30eb2847` into `.mishe-tauftauf/replays/ettercapgg2shell-w260/` reproduced
`RESULT PASS=25 FAIL=0`, rc 0, with runner sha256 unchanged; console
`replay-console.log`, finished 09:54:46Z. The first replay from `9f1ae4bc`
correctly `PIN_FAIL`ed because the pinned fix patch was not yet tracked;
`30eb2847` tracks it. Next: operator admission only (witness replay closed in
W261). Route and generated wake units are person-reserved; do not add them here.

## W261 (2026-11-26 10:33–10:3xZ): witness verdict ESTABLISHED AS LABELED

Independent clean-archive replay of `run-all.sh` hash `35c3f7d5…458958c4`
(identical in worktree, `a6d617ee` and `git archive a6d617ee` subtree):
10:37:36Z–10:37:38Z, rc 0, 25 PASS / 0 FAIL. Archived evidence was removed
and both codeload tarballs were re-fetched by commit SHA; all four source/driver
pins, both extracted bodies and both function-start assertions held. GCC+Clang
ASan: `WRITE of size 13`, 0 bytes after the 30-byte region at verbatim
`src/dissectors/ec_gg.c:673`, `calloc(30, …)` at `poc.c:58`. Fixed ASan and
plain runs: `len=29`, no ASan; safe version: `len=3`, no ASan. Plain vulnerable
readback: chosen `b11=34` in bounds, suffix bytes `b30=69`/`b42=78` past the
allocation. No named adjacent object, pointer, wire path, command or r5; the
grade is unchanged. NIT: the earlier `poc.c:35` line reference in the frontier
report was stale (pinned driver line is 58), corrected in that report. Full
raw evidence: `.mishe-tauftauf/artifacts/witness-w261-ettercapgg2shell/detail.md`.
