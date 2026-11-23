# openexr2shell — status

Admitted 2026-11-23 ~11:5xZ under standing approval #6 as the 111th engine
route. Frontier staged this lane in W155 (commit `efba219`, staging DM #2559)
with pinned OpenEXR `v3.5.2` / `v3.5.3` sources, the fix commit
`7d7fbb1a5cf637ede04dae51123aff02d89c2b5c` and byte-exact `internal_zstd.c`
slices. Brief: `reports/frontier-openexr2shell.md`; pins and hashes:
`lab/frontier/openexr2shell/PINS.sha256`; provenance, verbatim pinned slices,
generated drivers and preserved negative results:
`lab/frontier/openexr2shell/PROVENANCE.md`. The two-pane inner tmux window 116
and its registry entry were already live; admission adopted them and created
no second window.

The hy4-flash `max_parallel: 3` route was added as the 111th role. The path,
debounce and `@openexr2shell` slice drop-in were minted with the exact
full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a` (`written 3,
removed 0`), followed by `systemctl --user daemon-reload`; the path unit is
enabled and active. Both `m2shell-wake@openexr2shell.service` and
`m2shell-wake-openexr2shell.path` were added to the site's owner resolver map
(223 entries). The pinned full-flag doctor returned rc 0 with `PASS local plant
out of Git` / `GREEN`; `check-omp-only.py` returned `GREEN (111 declared roles)`.
Admission changes no grade.

- Claim: GHSA-98rx-qpfv-qcwv, published 2026-10-31 by cary-ilm, High. No CVE
  number and no CWE are stated by the advisory (both UNKNOWN). Affected
  OpenEXR 3.5.0, 3.5.1, 3.5.2 and `main`; patched in 3.5.3. The advisory's
  692-byte file PoC, 4032-byte overrun and OpenImageIO flat-path reproduction
  are claims, not lab observations.
- Mechanism in pinned bytes: `compute_sorting_lookup()` returns the 2-byte
  channel subtotal as `splitPoint` and discards the full grid total.
  `sort2_4ByteChannels_tiled()` recomputes that total per row and runs
  `memcpy(outPtr + readIndex, inPtr + writeIndex, bitSize)` at pinned
  `internal_zstd.c.vuln:472`, with `outPtr` sized from the chunk leader's
  `unpacked_size`. An all-FLOAT part has no 2-byte channels, so `split == 0`
  and the pre-existing `if (split > uncompressed_size)` guard is vacuous.
  The fix hunk at pinned `internal_zstd.c.fixed:1373-1394` adds a `grid_total`
  loop and rejects with `EXR_ERR_CORRUPT_CHUNK`.
- Clean-archive replay: from `git archive HEAD` into
  `/tmp/openexr-replay.592N1Q`, `./run.sh` rc 0 and `./check.sh`
  `PASS=52 FAIL=0` with trace
  `27a2a815c1ac4fbb884a9b2f754a0ab3eabaac193f8c90b0a19bf2e44337c776`,
  matching frontier's value exactly.
- Rung 3: gcc and clang ASan report `heap-buffer-overflow`, `WRITE of size
  4096`, starting 0 bytes after a 64-byte region (4032 bytes past its end) at
  pinned `internal_zstd.c.vuln:472`; the fixed pin rejects the same geometry
  with rc 23 (`EXR_ERR_CORRUPT_CHUNK`) before the copy.
- Rung 4: plain build reports `b64=0x5a b4095=0x5a` against a `0xa5` canary;
  gdb records `bitSize=4096 n_hi=1024`, source `0x5a`, destination `0xa5`
  before and `0x5a` after the copy at `outPtr+64`.
- Ceiling: direct call over two verbatim pinned function slices; the only stub
  is `exr_coding_channel_info_t` reduced to `bytes_per_element`. No EXR header
  or chunk parsing, no sample-count table decoding, no ZSTD frame, no
  `exr_decoding_run()` ordering, no OpenEXR or OpenImageIO build, no image
  consumer, no process, socket or wire input. Chosen bytes are harness-supplied,
  not derived from a crafted file. No pointer or control-flow corruption, no
  command, no marker side effect and no witness verdict. Rung 5 is UNKNOWN.
- Preserved negatives: an initial clang ASan build exited 0 because it did not
  define `__SANITIZE_ADDRESS__`; buffered stdout hid pre-abort lines; a gdb
  breakpoint at pinned `:1393` never hit for the OOB case because the early
  return at `:1391` fires first. All were corrected and the original
  observations kept in `PROVENANCE.md`.

Ordered next work for the target mind: (1) build pinned 3.5.2 and 3.5.3 with
ASan and drive a crafted EXR through the real ZSTD decode path, confirming the
pinned frames and the 4096-byte overrun; (2) measure which live heap objects
the 4032-byte overwrite reaches before the process aborts and whether
file-supplied sample counts control the copied bytes; (3) only then consider a
bounded benign marker with vulnerable, fixed and safe-input controls and an
independent witness.
