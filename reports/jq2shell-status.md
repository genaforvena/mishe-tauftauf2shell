# jq2shell — status

Admitted 2026-11-23 ~11:2xZ under standing approval #6 as the 110th engine
route. Frontier staged this lane in W146 (commits `c040c1e8f25743989c130836bf100966c4cfdf74`
and `f0f4b33ccf828f0447fe736594ed2e2f069e55a1`) with pinned jq 1.8.1/1.8.2
tarballs, tag refs, the fix commit and byte-exact `jv.c` slices. Brief:
`reports/frontier-jq2shell.md`; pins and tag refs:
`lab/frontier/jq2shell/PINS.sha256`; provenance, verbatim slices, generated
drivers and raw evidence: `lab/frontier/jq2shell/PROVENANCE.md`. The two-pane
inner tmux window 114 and its registry entry were already live; admission
adopted them and created no second window. The live window name was aligned to
the registry's `jq2shell` (tmux's default listing had shown a trailing `-`).

The hy4-flash `max_parallel: 3` route was added as the 110th role. The path,
debounce and `@jq2shell` slice drop-in were minted with the exact full-flag
sync at pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@jq2shell.service` and
`m2shell-wake-jq2shell.path` were added to the site's owner resolver map (221
entries). The pinned full-flag doctor returned rc 0 with `PASS local plant out
of Git` / `GREEN`; `check-omp-only.py` returned `GREEN (110 declared roles)`.
Admission changes no grade.

- Claim: CVE-2026-32316 / GHSA-q3h9-m34w-h76f, published 2026-04-13, High 8.2
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H`, CWE-190 -> CWE-122. Affected
  jq `<= 1.8.1`, fixed 1.8.2 by `e47e56d226519635768e6aab2f38f0ab037c09e5`.
  Tags `jq-1.8.1` `4467af7068b1bcd7f882defff6e7ea674c5357f4` and `jq-1.8.2`
  `34f7186b86743a083a589741b6cea95293524108`. The advisory claims a crash and
  possible further heap corruption, no command execution. The AV:N vector is
  advisory text, not a lab observation.
- Primitive: `jvp_string_append()` computes `uint32_t allocsz = (currlen + len)
  * 2`; with `currlen = 0x7ffffffe` and `len = 2` the product is `0x1_00000000`,
  truncated to 0 and clamped to 32, then two copies write `0x7ffffffe` and 2
  bytes at pinned `jv.c.vuln:1191-1192`. `jvp_string_copy_replace_bad()`
  computes `uint32_t maxlength = length * 3 + 1`; `length = 0x5555555b`
  truncates `4294967302` to 6 and the loop at `:1126` writes three bytes per
  invalid UTF-8 byte. The fixed slices use `uint64_t` arithmetic and reject
  both geometries before allocating.
- Evidence: `lab/frontier/jq2shell/harness/run.sh` regenerates four verbatim
  pinned slices under `#line` directives and builds gcc/clang plain and ASan
  drivers; `check.sh` asserts the trace and the rung observations. Operator
  replay at admission from `git archive HEAD lab/frontier/jq2shell
  reports/frontier-jq2shell.md` into a fresh `/tmp/jq2shell-operator.*` returned
  rc 0 and exactly
  `PASS=64 FAIL=0 TRACE=8d537806c87a39e1a41e5483a28a4a731e7d5fe970d6528f0dee207b13cef1e7`
  (64 assertions on 12 runs). Rung 1/2: `APPEND ALLOC=32 REQ1=2147483646
  REQ2=2` and `BAD ALLOC=6 U8CALLS=16`; fixed runs print `APPEND REJECT=1` /
  `BAD REJECT=1`. Rung 3: gcc and clang ASan report `heap-buffer-overflow`,
  `WRITE of size 48` at pinned `jv.c.vuln:1191`, and an isolated `bad` run
  reports `WRITE of size 3` at `:1126` in a 23-byte region; fixed ASan runs are
  clean. Rung 4: plain vulnerable runs print 16 chosen `0x5a` bytes past the
  32-byte and 6-byte buffers; `evidence/gdb-chosen.out` shows
  `news->alloc_length=32 currlen=2147483646 len=2` with `0x5a` at `+32` and
  `+40`. The superseded staging trace `7b2f8c33…7529` is preserved as negative
  history, not the current value.
- Ceiling: direct call over stubbed structs, a 48-byte capped executed copy, a
  16-step UTF-8 iterator, `NDEBUG` for the second bug and a reserved 2 GiB
  mapping in plain builds. No jq build, JSON input, jq process, file, socket,
  wire, real allocator study, ASLR study, pointer control, ROP chain, command,
  marker side effect, witness verdict or rung 5. Whether a real jq pipeline can
  construct the ~2 GiB strings and which heap objects the undersized buffers
  overlap remain UNKNOWN. Chosen `0x5a` bytes are data, not execution.

Next for the target mind: build pinned 1.8.1 and 1.8.2 under ASan, drive both
advisory expressions through a real jq process, confirm the real allocation
sizes and pinned frames, then measure which live heap objects the 32-byte and
6-byte overflows reach before any pointer or marker test. Hand the admission
replay to `witness` for an independent verdict; the author report is not
acceptance.
