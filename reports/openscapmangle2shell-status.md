# openscapmangle2shell — status (STAGED 2026-11-26 W295, admission owed)

Frontier staged this candidate from pinned raw bytes on 2026-11-26. The
operator admits targets under standing #6 and a witness replays claims;
nothing here is independent acceptance. No window existed for this target
before this wake; the live two-pane window is recorded below.

Artifacts: brief `reports/frontier-openscapmangle2shell.md`, charter
`charters/openscapmangle2shell.md`, seed wall
`.mishe-tauftauf/walls/openscapmangle2shell.md`, harness and pins
`lab/frontier/openscapmangle2shell/` (PROVENANCE.md, PIN_HASHES.txt,
verbatim sink copies, run-all.sh and its traces).

Grade at handoff: **rung 3 ASan-confirmed heap-buffer-overflow WRITE of size 1
at verbatim `src/DS/sds.c:884`, 0 bytes after an 8-byte region allocated at
`:860`, on GCC and clang with the fixed pin and safe vector clean.**
**Rung 1 and rung 2 NOT CLAIMED** (plain build exits 0), **rung 4 NOT CLAIMED**
(constant NUL immediately after the buffer; no chosen byte, offset or pointer),
**rung 5 NOT CLAIMED** (sink-only local harness, no CLI or wire path).
`run-all.sh` PASS=5 FAIL=0 at 22:20Z. The advisory's empty-string vector did
not trap under GCC ASan on this build: preserved as an UNKNOWN negative.

Control gap: no upstream tagged fixed release. The fixed pin comes from main
commit `5f1f2bccd4b5f85e44a21a0ce3c854fbb65a2163`; the vendor fixed control
is RHSA-2026:103520 (not built here).

Owed: operator admission decision, independent witness clean-archive replay,
then a bounded rung-2 experiment on a full `oscap ds sds-compose` build if the
new mind judges one worthwhile. Registered grade R1 — / R2 — / R3 ✓ / R4 — /
R5 —; R4/R5 NOT CLAIMED.
