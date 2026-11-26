# sdcppimatrix2shell — status (STAGED 2026-11-26 21:44Z)

Staged by frontier W293 from pinned stable-diffusion.cpp tags
`master-742-1a13107` (affected) and `master-763-4fcc6fe` (fixed). Brief
`reports/frontier-sdcppimatrix2shell.md`, charter
`charters/sdcppimatrix2shell.md`, seed wall
`.mishe-tauftauf/walls/sdcppimatrix2shell.md`, harness, pins and raw traces
`lab/frontier/sdcppimatrix2shell/`. Operator admission under standing #6 and
independent witness replay are owed; nothing here is independent acceptance.

Artifacts: brief, status, charter, seed wall, PROVENANCE, pinned source files,
fix patch, input generator, `run-all.sh` and eight cases with rc files. The
two-pane inner-socket tmux window is recorded in
`.mishe-tauftauf/operator/window-registry.json`.

Grade at handoff: **rung 1 + rung 2 on the plain build** (deterministic
298-byte local-file trigger; `double free or corruption (out)`, rc 134) and
**rung 3 ASan-confirmed heap-buffer-overflow** at verbatim
`src/imatrix.cpp.vuln:302` via shipped `load_imatrix()` `:168`, 0 bytes after
the 4-byte `e.values` allocation from `:288`. Fixed build rejects the same
file with rc 3 and the new diagnostic; safe-input controls clean on both
pins in ASan and plain builds. `run-all.sh` **PASS=17 FAIL=0** at 21:42Z.

**Rung 4 NOT CLAIMED, rung 5 NOT CLAIMED.** ASan traps on the OOB READ half
of `e.values[i] += tmp[i]`; the write half and the `e.counts[i]` write were
not separately observed, and no chosen-byte/pointer/marker/command was
demonstrated. No wire path or live service was tested. The advisory's
`sd-cli -M convert --imat-in` SIGSEGV claim was not re-tested in this wake.

Register grade R1 ✓ / R2 ✓ / R3 ✓ / R4 — / R5 —.
Owed: clean-archive replay by the witness, then a bounded plain-build heap
layout experiment and, separately, a shipped-`sd-cli` replay at both pins.
