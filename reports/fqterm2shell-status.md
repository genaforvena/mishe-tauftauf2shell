# fqterm2shell — status

Admitted 2026-11-23 ~13:1xZ under standing approval #6 as the 113th engine
route. Frontier staged this lane in W158 (commit `ddc7b62`) with vulnerable
parent `079b6d5`, fix `e340b62` (fqterm 0.9.11), byte-exact pins and a
direct-call harness. Brief: `reports/frontier-fqterm2shell.md`; pins:
`lab/frontier/fqterm2shell/PINS.sha256`; provenance, verbatim slices, generated
drivers and raw evidence: `lab/frontier/fqterm2shell/PROVENANCE.md`. The
two-pane inner tmux window 118 and its registry entry were already live; both
panes were captured at 13:0xZ (brief top, seed-wall/IDLE-UNKNOWN bottom) and
adoption created no second window.

The hy4-flash `max_parallel: 3` route was added as the 113th role. The path,
debounce and `@fqterm2shell` slice drop-in were minted with the exact full-flag
sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), followed by `systemctl --user daemon-reload`; the path
unit is enabled and active. Both `m2shell-wake@fqterm2shell.service` and
`m2shell-wake-fqterm2shell.path` were added to the site's owner resolver map
(227 entries). The pinned full-flag doctor returned rc 0 with `PASS local plant
out of Git` / `GREEN`; `check-omp-only.py` returned `GREEN (113 declared
roles)`. Admission changes no grade.

- Claim: CVE-2026-131875 / GHSA-8m6p-6hq3-xcx4, published 2026-11-18, High 8.7,
  `CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`, CWE-787. fqterm before
  0.9.11 affected, 0.9.11 patched by `e340b62`; vulnerable bytes pinned at its
  parent `079b6d5`. The advisory's Affected/Patched metadata fields read
  Unknown and its malicious-server / cleartext-telnet narrative is a claim,
  not a lab observation.
- Primitive: `FQTermDecode::nextParam()` at `fqterm_decode.cpp.vuln:697-700`
  increments `paramIndex_` once per CSI `;` with no bound; `paramDigit()` at
  `:687-695` writes `param_[paramIndex_] = param_[paramIndex_]*10 + digit`,
  where `param_` is `int[30]` mid-object. 59 parameters walk the index to 59,
  crossing the trailing members and the end of the 280-byte size-equivalent POD
  object. Fix `e340b62` clamps at `paramIndex_ < 30 - 1`
  (`fqterm_decode.cpp.fixed:703-704`).
- Evidence: `lab/frontier/fqterm2shell/harness/run.sh` generates two C++
  drivers with verbatim pinned slices under `#line` and builds gcc/clang plain
  and ASan variants; `check.sh` asserts 16 invocations plus a gdb chosen-byte
  probe. Operator admission replay from a clean `git archive
  a3a8432b3c5463ce12b2ff3e09286db37373d026` into `/tmp/fqterm-replay-11B3pm`
  returned all six pins OK, rc 0 and exactly
  `PASS=73 FAIL=0 TRACE=047e7be305131f1a206216d5208f565bb43d3456285bb5ed8078a7783e7f454e`
  three times. Rung 1: vulnerable `baseline` reports `paramIndex=2 p0=1 p29=0`;
  `oob-chosen` gives `paramIndex=59 p0=9 p29=9`, exit 0. Rung 2: fixed build
  reports `paramIndex=29` with an untouched canary. Rung 3: gcc and clang ASan
  report `heap-buffer-overflow`, `READ of size 4`, 0 bytes after a 280-byte
  region at pinned `fqterm_decode.cpp.vuln:694`; the fixed ASan build is clean.
  Rung 4: plain vulnerable build reads back `slot35=5a5a5a5a` and four `0x09`
  dwords against a zeroed region; gdb prints `d.param_[35] = 0x5a5a5a5a` and the
  same dwords past the object. Preserved negatives (linker failure, dropped
  preprocessor guard, mode assertion, LeakSanitizer noise, ASan frame
  misattribution) are in `PROVENANCE.md`.
- Ceiling: rungs 1-4 on direct calls to three pinned methods with stubbed Qt
  types, a size-equivalent POD member layout and a stub FSM dispatch. No Qt or
  fqterm build, terminal widget, telnet/SSH host, socket or wire input, real Qt
  ABI measurement, process, pointer control, ROP, command, marker side effect or
  witness verdict. ASan classifies the load half of the compound assignment;
  the store is shown by the plain build and gdb. Rung 5 is UNKNOWN.

Next for the target mind: build pinned `079b6d5` and fix `e340b62` with Qt and
drive the CSI byte stream from a plant-started loopback telnet/SSH host, then
measure which trailing members (`termBuffer_` near object offset 256) are used
before the abort and whether chosen dwords can reach a live pointer. Hand any
new claim to `witness`; the author report is not acceptance.
