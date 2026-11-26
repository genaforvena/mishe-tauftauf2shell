# oiiocineon2shell — staged status (W297, 2026-11-26)

Frontier STAGED this candidate on 2026-11-26 from verbatim upstream tags;
the operator has NOT admitted it. Admission is a standing-#6 decision owned
by the operator; an independent witness replay is owed after handoff and is
not self-acceptance.

Claim: CVE-2026-59181 / GHSA-xh8r-vmqq-56pp (CNA `GitHub_M`, advisory
2026-07-10, CVE record 2026-09-18), CWE-121/CWE-787, CVSS 6.1. Vulnerable
`v3.2.0.2-dev`; fixed `v3.2.0.3-beta1` (also 3.0.20.0 and 3.1.15.0 branches).
Fix PR 5250 adds a 1-8 `nchannels` guard in `CineonInput::open()`.

Artifacts: brief `reports/frontier-oiiocineon2shell.md`, charter
`charters/oiiocineon2shell.md`, seed wall
`.mishe-tauftauf/walls/oiiocineon2shell.md`, harness and pins
`lab/frontier/oiiocineon2shell/` (`PROVENANCE.md`, 37 pinned SHA-256
manifest, verbatim `cineoninput.cpp` and `libcineon/` trees from both tags,
fix patch, verbatim sink generator, driver, three local `.cin` headers and
traces). A live two-pane window named `oiiocineon2shell` is registered in
`.mishe-tauftauf/operator/window-registry.json` before this status is handed
off; no duplicate window is needed.

Grade at handoff: **rung 3 ASan-confirmed stack-buffer-overflow WRITE of size
8 at verbatim pinned `cineoninput.cpp:215`, first store past `strings[8]`, on
GCC `-O1` and clang `-O0`.** Fixed pin rejects count 255 with no ASan,
safe(8)/valid(1) clean on both pins. **Rung 1 and rung 2 NOT CLAIMED** (plain
build exits 0), **rung 4 NOT CLAIMED** (no chosen byte, adjacent live object,
pointer or control flow), **rung 5 NOT CLAIMED** (direct sink call, local file).
`run-all.sh` PASS=13 FAIL=0 at 23:00Z.

Control gaps: the advisory's adjacent `Reader cin` frame is not reproduced;
clang `-O1` optimized the store away (negative preserved, clang uses `-O0`);
three small OIIO helper headers are frontier-authored build shims, not
upstream OIIO; no full `iinfo` consumer or wire path is built. OSV lookup for
the GHSA returned 404 (negative preserved).

Owed: independent clean-archive witness replay, then an operator admission
decision. Registered grade R1 — / R2 — / R3 ✓ / R4 — / R5 —; R4/R5 NOT CLAIMED.
