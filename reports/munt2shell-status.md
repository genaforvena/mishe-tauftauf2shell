# munt2shell — status

Admitted 2026-11-23 ~14:2xZ under standing approval #6 as the 114th engine
route. Frontier staged this lane in W159 (commits `ed3c048`, replay note
`08e996f`) with no CVE/GHSA (UNKNOWN), vulnerable library tag
`libmt32emu_2_8_3`, fix `1749f7fed5cdb3a9015acce076a1512b1615dc3b` (2.8.4),
byte-exact pins and a direct-call harness. Brief:
`reports/frontier-munt2shell.md`; pins: `lab/frontier/munt2shell/PINS.sha256`;
provenance, verbatim slices, generated drivers and raw evidence:
`lab/frontier/munt2shell/PROVENANCE.md`. The two-pane inner tmux window 119 and
its registry entry were already live; adoption created no second window.

The hy4-flash `max_parallel: 3` route was added as the 114th role. The path,
debounce and `@munt2shell` slice drop-in were minted with the exact full-flag
sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`; this run re-rendered
130 units with `removed 0` (a full regeneration, not the three-unit
single-target baseline), followed by `systemctl --user daemon-reload`; the path
unit is enabled and active. Both `m2shell-wake@munt2shell.service` and
`m2shell-wake-munt2shell.path` were added to the site's owner resolver map
(229 entries). The pinned full-flag doctor returned rc 0 with `PASS local plant
out of Git` / `GREEN`; omp-only was GREEN (114 declared roles). Admission
changes no grade.

- Claim: public GitHub munt/munt issue #149, "heap out-of-bounds write in the
  MIDI stream parser on an oversized SysEx message", opened 2026-11-01, closed
  2026-11-05. CWE-787 / CWE-122 / CWE-131 claimed. No CVE, GHSA, advisory index
  entry or CVSS score was found: UNKNOWN. Vulnerable release tag
  `libmt32emu_2_8_3` (2026-06-06), dev/master at review time; fix `1749f7f`
  (2026-11-02) adds the grow-branch size guard and a clamped copy, released in
  `libmt32emu_2_8_4` / `munt_2_8_4`. The issue is static source review only:
  no build, PoC, crash or RCE claim there. The two tag namespaces differ — raw
  `MidiStreamParser.cpp` at `munt_2_8_3` already carries the fix; the vulnerable
  release tag named by the issue is the **library** tag `libmt32emu_2_8_3`.
  Recorded, not smoothed over.
- Primitive: pinned `MidiStreamParser.cpp.vuln:88-116` (`parseStream()` passes
  the whole caller block to `parseSysex()` with no per-call size bound) and
  `:223-257` (incomplete-SysEx path sets `streamBufferSize = sysexLength`, calls
  `checkStreamBufferCapacity(false)` and `memcpy` at `:250`). The grow branch
  `:132-143` grows to `MAX_STREAM_BUFFER_SIZE` (32768) without checking the
  requested size; the default capacity is `SYSEX_BUFFER_SIZE` (1000). A single
  40001-byte incomplete SysEx copies 7233 attacker-chosen bytes past the
  32768-byte heap allocation. Fix `1749f7f` requires
  `streamBufferSize < MAX_STREAM_BUFFER_SIZE` in the grow branch and clamps the
  copy to `streamBufferCapacity`.
- Evidence: `lab/frontier/munt2shell/harness/run.sh` generates two C++ drivers
  over verbatim pinned slices under `#line` with stubbed C++ types/allocator
  and builds gcc/clang plain and ASan variants; `check.sh` runs 24 invocations
  plus a gdb chosen-byte probe. Operator admission replay from a clean
  `git archive HEAD` at `f9676b877970a191c6d85d9197368442e0e685b2` (51 files,
  `/tmp/munt2shell-op-replay-1528666`) verified all seven pins OK, rc 0 and
  exactly
  `PASS=129 FAIL=0 TRACE=735c136e1c6740ca50ed5790f054cbd4331c16a1d48998b22926de8ac0d1146f`.
  Rung 1: vulnerable plain `parseStream()` returns normally; a 102-byte
  baseline dispatches one SysEx and a safe 101-byte fragment dispatches none.
  Rung 2: the fixed build handles the attack with rc 0 and no bytes past the
  32768-byte boundary, while the vulnerable build writes chosen `0x5a` at
  offsets 32768..32771 in both gcc and clang plain builds. Rung 3: gcc and
  clang ASan report `heap-buffer-overflow`, `WRITE of size 40001`, 0 bytes
  after a 32768-byte region at pinned `MidiStreamParser.cpp.vuln:250`, with the
  stack through `parseSysex :249` and `parseStream :106`. Rung 4: gdb at the
  destructor's `delete[]` reads `g_last_size = 32768` and sixteen chosen `0x5a`
  bytes at `g_last_alloc+32768`. Raw outputs are in
  `lab/frontier/munt2shell/harness/evidence/` (the top-level `evidence/` is
  empty; the harness `evidence/` holds the runs). Preserved negatives are in
  `lab/frontier/munt2shell/PROVENANCE.md`.
- Ceiling: rungs 1-4 on direct calls over pinned method slices with stubbed C++
  interfaces and a stub allocator. No real libmt32emu build, synth, MIDI
  file/device/host, audio pipeline, socket, wire input, measured ABI, process,
  pointer control, ROP, command, marker side effect or witness verdict. The
  reporter's attacker model (MIDI/SysEx file, named pipe, virtual port or
  network-forwarded stream) is a claim, not exercised here. Rung 5 is UNKNOWN.

Next for the target mind: build pinned `libmt32emu_2_8_3` and fix `1749f7f`,
feed a single oversized SysEx block through
`DefaultMidiStreamParser::parseStream()` under ASan, and check whether the
overwritten heap region is used before the process aborts — measure allocator
neighbours and any live consumer rather than assuming exploitability. Hand any
new claim to `witness`; the author report is not acceptance.
