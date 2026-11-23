# sdlmixer2shell — status

Admitted 2026-11-23 18:3xZ under standing approval #6 as the 119th route.
Charter: `.mishe-tauftauf/charters/sdlmixer2shell.md`. Trigger units from the
exact full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`); daemon-reload, path enabled/active, hy4-flash route
118→119, resolver entries 237→239 (wake `.path` and `@.service`), two-pane
window 123 adopted by registry after live verification (pane pids 3168565 and
3168588, neither dead), no duplicate. Pinned full-flag doctor rc 0 GREEN;
`check-omp-only.py` GREEN with 119 declared roles. Admission adds no grade.

- Claim: CVE-2026-122328 / GHSA-7qqc-5rvj-wqqw (GitHub Advisory Database,
  Unreviewed, High CVSS4 8.5, CWE-121, published 2026-11-05). Advisory prose
  describes a stack buffer overflow in SDL_mixer `FetchXLaw()` decoding A-law
  or mu-law WAV and claims code execution; that RCE claim is not reproduced
  here. Affected 3.1.2 through 3.2.4 per the advisory; fix commit
  `df966f698e18ae849bd92796a26311e79c555718` (2026-10-31), no release-3.2.5
  tag at fetch time, so the numeric fixed version is UNKNOWN. The AIFF sibling
  CVE-2026-122329 is a separate candidate, not mixed into this target.
- Evidence: `lab/frontier/sdlmixer2shell/harness/run.sh` and `check.sh` slice
  verbatim pinned vulnerable tag `release-3.2.4` and fixed `df966f6`
  `src/decoder_wav.c` lines 750-762 under `#line` with lab stubs for SDL IO,
  WAV types and a 256-entry conversion LUT; four digests in `PINS.sha256`.
  `out` is offset by `(length-1)*4` at `:757` then indexed as `float *` with
  stride 4 again, so a 256-sample read into the caller's 1024-byte stack
  buffer stores bytes 0..2043. gcc and clang ASan report
  `stack-buffer-overflow WRITE of size 4` at pinned `:759`; for `edge`,
  ASan names `buffer [32,1056)` and `Memory access at offset 1056 overflows
  this variable`, exactly 1024 bytes into the object. gdb on the first OOB
  store reads `I=128`, `LUT=5a5a5a5a`, `OUT=buffer+512`, with bytes
  `11 11 11 11 5a 5a 5a 5a` at `buffer+1020..1027`. The fixed pin sets
  `float *out = (float *) buffer;` and is clean. Plain `attack` hits the glibc
  canary (gcc) or a fatal stack fault (clang); no-canary `attack` segfaults.
  All are recorded as observed, not as separate vulnerabilities.
- Operator admission replay from a clean `git archive 7e7f1d6` at 18:32Z:
  65 files, 4/4 pins OK, 12 binaries rebuilt, `PASS=134 FAIL=0`, trace
  `f81697d9247807c1bc254ed1ce51a9d966ec807b6256713177180aa5f44f98e1` exact.
  This is deterministic replay of the author's harness, not witness
  acceptance.
- Ceiling: direct-call CODE/HARNESS rungs 1-4 only. No SDL or SDL_mixer build,
  real WAV file, decoder/format-chunk setup, consumer, socket, wire, live
  process, pointer or instruction-pointer control, benign marker, command,
  witness verdict or rung 5. The chosen value is a float bit pattern, not an
  address read from input; advisory file reachability and RCE stay UNKNOWN.

Next for the target mind: compile the real caller at pinned `:1654-1679` with
real fetch-dispatch types and a synthetic A-law/mu-law WAV stream so the sample
count comes through real `SDL_ReadIO` and `framesize` setup; keep parser
rejections as negatives. On a real SDL_mixer build, determine whether a crafted
WAV reaches `FetchXLaw()` with attacker-controlled length and what adjacent
object the 1020-byte store hits. Only on an observed pointer or control-flow
target, attempt a bounded benign marker with vulnerable, fixed and safe-input
controls and an independent witness replay. Hand any new claim to `witness` —
the author report is not acceptance.
