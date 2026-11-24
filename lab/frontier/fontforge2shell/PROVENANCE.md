# PROVENANCE — fontforge2shell W196

All external reads were provisioning on 2026-11-24 04:33-04:34Z:
- VulnCheck advisory page for CVE-2026-135295 (claim, versions, CVSS,
  references).
- `https://raw.githubusercontent.com/fontforge/fontforge/20251009/fontforge/fvimportbdf.c`
  (2530 lines, sha256 `df766f9c…81f0eb30d`), stored under `pinned/`.
- `https://github.com/fontforge/fontforge/commit/65e80b5dfb6691a1c8a532cfbb8ec905949e0c9a.patch`
  (23 lines, sha256 `f2745243…5e99175`), stored under `pinned/`.
- GitHub commit API for the fix parent hash `c83ff048…e692218` and stats
  (1 file, +1/-1).

No probe, scan or client run touched any external host. All builds and
runs are local, with an in-memory `fmemopen()` table; no loopback service
was needed. `harness.c` copies the pinned function and PCF helpers verbatim,
with `figureProperEncoding()` stubbed and minimal struct stand-ins; the
`FIXED` branch is the verbatim fix line. `run-all.sh` rebuilds five
binaries, runs the attack and two controls, probes chosen bytes with gdb,
and writes `evidence.log` with per-file sha256s.

An author-side clean `git archive e5e4a65` replay is recorded in
`REPLAY.md`: 5/5 expected RCs and normalized hash `56fd8ada…5633bb`.
Independent witness replay (message #3309, clean archive of `13a2a94`,
gcc 13.3.0 / gdb 15.1) confirmed the same matrix and bytes and graded
rungs 1-4 ESTABLISHED at the direct-call scope, NO r5.

W2 (2026-11-24 07:4xZ): no new external reads. The vulnerable source
tarball and pinned patch provisioned in W1 were reused; the extra plain
Debug builds (`build-plain/`, `build-fixed-plain/`) and all gdb runs were
local and loopback-free. The only new input file is the already-pinned
`truncated.pcf` driven through the real headless scripting `Import()`.
W2 transcripts and their sha256s are recorded in `REACHABILITY.md`.
