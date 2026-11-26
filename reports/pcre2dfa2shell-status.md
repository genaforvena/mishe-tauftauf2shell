# pcre2dfa2shell — ADMITTED (164th target mind, 2026-11-26)

Brief: `reports/frontier-pcre2dfa2shell.md`. Lab: `lab/frontier/pcre2dfa2shell/`.
Claim: CVE-2026-86145 / GHSA-3r4p-g7gg-ppmf, PCRE2 10.32–10.47 DFA
workspace-reuse heap OOB write; fixed in 10.48 by `c932e704…` (advisory cites
a 404 SHA, preserved). State: **ADMITTED 07:2xZ under standing #6**; window 172
adopted from frontier (panes %346/%347 live, no duplicate). Route and three
generated wake units are not yet present in the current omp-only/doctor
readings, person-reserved. Independent witness W252 verdict: ESTABLISHED AS
LABELED (07:1xZ), no grade change, NO r5.

Evidence: `lab/frontier/pcre2dfa2shell/run-all.sh` on pinned 10.47/10.48
tarballs with the public-API harness `harness/dfa.c`: vulnerable 10.47 GCC+Clang
ASan `WRITE of size 4` at verbatim `src/pcre2_dfa_match.c:686`, plain rc=139;
fixed 10.48 rc=-63 HEAPLIMIT in all three builds. Grade: rung 3 verbatim /
rung 4 PARTIAL (no chosen bytes, pointer control, wire path, command or r5).

Operator replay: unmodified `run-all.sh` sha256
`110f17e80300c2eede2390d39cd2eb1217c9756f9497c8971b315b4aa986b1aa` from a
clean `git archive HEAD` (pinned tarballs hash-verified locally):
`RESULT PASS=6 FAIL=0` rc 0. Replay tree:
`.mishe-tauftauf/replays/pcre2dfa2shell-admission-071234`. Harness precondition:
`pcre2_dfa_match` needs a non-NULL caller workspace; the earlier
NULL-workspace result (-51) is preserved as a negative.

- Witness W252: unmodified `run-all.sh` replayed three times (fresh clean
  archive at 184.51 s, cached clean archive, serial in-tree), 6 PASS / 0 FAIL
  each; GCC+Clang ASan WRITE-4 at verbatim `:686` via the public API, plain
  SIGSEGV at the same sink under gdb (`rlevel=9`, not stack exhaustion), all
  10.48 controls `-63`. Both tarballs and the fix patch re-fetched; benign
  patterns produced no ASan report. Detail:
  `.mishe-tauftauf/artifacts/witness-w252-pcre2dfa2shell/detail.md`.
- Next: plain-allocator adjacent-field primitive only if a measured path
  exists; no grade change from the witness replay.
