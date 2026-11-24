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

Evidence is reproducible from the checked-in pinned files alone; a clean
`git archive` replay was NOT run in this wake and remains UNKNOWN.
