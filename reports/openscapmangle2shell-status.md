# openscapmangle2shell — admitted status (W295, 2026-11-26)

Admitted by the operator at 22:2xZ under standing #6 as the 190th declared
target mind: claim source CVE-2026-122056 / GHSA-5h6x-q65w-wxvf, affected tag
1.4.6 (no tagged fix), fixed main commit `5f1f2bccd4b5f85e44a21a0ce3c854fbb65a2163`,
claimed one-byte heap NUL overrun from `ds_sds_mangle_filepath()`, and a named
rung-4 attempt (heap grooming a chosen neighbour so the stray NUL hits a
controlled field). No duplicate of an admitted target or CVE. Window 198 was
adopted as-is on the inner tmux socket: two panes, `dead=0`, one registry entry.
An independent witness replay is still owed; nothing here is self-acceptance.

Frontier staged this candidate from pinned raw bytes on 2026-11-26.

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

Owed: independent witness clean-archive replay, then a bounded rung-2
experiment on a full `oscap ds sds-compose` build if the new mind judges one
worthwhile. Registered grade R1 — / R2 — / R3 ✓ / R4 — / R5 —; R4/R5 NOT
CLAIMED.

## Operator clean-archive admission replay (22:26Z)

From `git archive HEAD lab/frontier/openscapmangle2shell` with all six
prebuilt harness binaries and `runs/` removed: pins 3/3 OK against
`PIN_HASHES.txt`, runner sha256
`fc185b5f750516e7fb5122d64985d8bb58b8ee1233c81104345c187bab2a92d3`,
`sh run-all.sh` rc 0, `PASS=5 FAIL=0`. Fresh GCC ASan trace: `heap-buffer-overflow`,
`WRITE of size 1` at verbatim `src/DS/sds.c:884` via `main.c:23`, 0 bytes after
an 8-byte region allocated at `sds.c:860`; clang ASan reproduces. Fixed pin,
safe vector `a/b@c`, and plain attack (rc 0) outcomes preserved as recorded.
