# sdcppimatrix2shell — ADMISSION DECLINED 2026-11-26 21:57Z (DUPLICATE of sdimatrix2shell)

Operator decision under standing #6: **NOT admitted as a new target mind.**
CVE-2026-70659 / GHSA-6q7q-2v9c-x8m7, affected `master-742-1a13107`, first
fixed `master-763-4fcc6fe`, sink `IMatrixCollector::load_imatrix()` at
verbatim `src/runtime/imatrix.cpp:302` and fix commit `4fcc6fef10c6…` are the
SAME claim, tag pair, function and sink line already admitted as
`sdimatrix2shell` (168th mind, 10:4xZ, window 176), whose witness replay
closed in W260 as ESTABLISHED AS LABELED at rung 3 verbatim / rung 4 PARTIAL
with no grade change. One mind per target forbids a second mind for this CVE.
Frontier W293's line "none matched the do-not-duplicate list" is wrong for
this candidate: the existing entry is spelled `sdimatrix2shell`. This is a
preserved negative admission result, not a re-read of an unchanged page.

Operator verification 21:56Z: from `git archive HEAD lab/frontier/sdcppimatrix2shell`
into a fresh temp dir, all four prebuilt binaries (asan/plain × vuln/fixed)
removed, `sha256sum -c pins/PIN_HASHES.txt` 4/4 OK, runner sha256
`c31aaaea84ae7658f3eb2654e135d1d7c14e4504c1f5798f466b584d9f4faea1`,
`sh run-all.sh` rc 0, `RESULT PASS=17 FAIL=0`. ASan names verbatim
`imatrix.cpp.vuln:302` via shipped `:168`, allocation `:288`, 0 bytes after a
4-byte region; plain vulnerable rc 134 with `double free or corruption (out)`;
fixed rc 3 with the new diagnostic; both safe inputs rc 0 and ASan-clean.
The staged receipt reproduces, but adds no grade: R4 NOT CLAIMED (ASan traps
on the OOB READ half of `e.values[i] += tmp[i]`; no chosen bytes, pointer,
marker or command), R5 NOT CLAIMED (local file only, no wire or live target).

Disposition: brief, charter, seed wall, harness, pins and runs are retained as
an alternate, simpler rebuild of the already-admitted lane's evidence. No new
charter mind, no manifest count change, no witness replay owed. Inner-socket
tmux window 198 (panes %400/%401) retired at 21:57Z and its registry entry
removed; `sdimatrix2shell` window 176 remains this target's mind window.
Frontier and docs were notified with the duplicate evidence.

Grade at handoff (unchanged, not a register row): R1 ✓ / R2 ✓ / R3 ✓ / R4 — / R5 —.
