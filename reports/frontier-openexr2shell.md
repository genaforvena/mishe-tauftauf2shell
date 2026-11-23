# Frontier brief: OpenEXRCore ZSTD grid-total overflow — GHSA-98rx-qpfv-qcwv (openexr2shell)

**STAGED 2026-11-23 W155 — direct-call harness evidence, a live registered
two-pane window (inner socket index 116, name `openexr2shell`) and a staging
DM to the operator (#2559) exist; operator admission and an independent
witness verdict are pending.** Byte-exact pins and hashes:
`lab/frontier/openexr2shell/PINS.sha256`; harness provenance
including preserved negative results:
`lab/frontier/openexr2shell/PROVENANCE.md`. Frontier owns no further work on
this target.

## 1. Verified ground truth

- Advisory: GHSA-98rx-qpfv-qcwv, published 2026-10-31 by cary-ilm, High,
  "Missing grid-total bound in ZSTD deep decode causes heap out-of-bounds
  write in OpenEXRCore" —
  https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-98rx-qpfv-qcwv
  No CVE number is stated in the advisory text: **UNKNOWN**. CWE is not
  stated either; the described primitive is an out-of-bounds heap write.
- Affected: OpenEXR 3.5.0, 3.5.1, 3.5.2 and `main`; patched: 3.5.3. The
  advisory says 3.4.x and earlier have no ZSTD codec and are unaffected;
  that and its 692-byte file PoC, 4032-byte overrun and OpenImageIO flat-path
  reproduction are **claims from the advisory**, not reproduced in this lab.
- Upstream fix `7d7fbb1a5cf637ede04dae51123aff02d89c2b5c` (2026-10-06,
  "bound the ZSTD grid total against uncompressed_size (#2713)") adds the
  grid-total check. The vulnerable pin is tag `v3.5.2`; the fixed pin is
  `v3.5.3`, both read only from upstream. No target by this name appears in
  the plant's do-not-duplicate list, brief set or registry.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; the pinned bytes live in
`src/internal_zstd.c.{vuln,fixed}` and are included verbatim under `#line`
control in the generated drivers.

`compute_sorting_lookup()` accumulates `writeCount` over 2-byte channels,
returns that subtotal as `splitPoint`, then keeps accumulating the 4-byte
channels and discards the final full total. `sort2_4ByteChannels_tiled()`
recomputes that full total per row in its decode branch: `bitSize = n_hi *
channels[i].bytes_per_element` and `memcpy(outPtr + readIndex, inPtr +
writeIndex, bitSize)` at pinned `internal_zstd.c.vuln:472`. `outPtr` is
`uncompressed_data`, sized from the chunk leader's `unpacked_size`, and
nothing bounds the grid-derived total against it. An all-FLOAT part has no
2-byte channels, so `split == 0` and the pre-existing
`if (split > uncompressed_size)` guard is vacuous.

The fix at pinned `internal_zstd.c.fixed:1373-1394` keeps that split check and
adds a `grid_total` loop over the same grid; it returns
`EXR_ERR_CORRUPT_CHUNK` when the total exceeds or does not equal
`uncompressed_size`, before the inverse sort runs. The v3.5.3 source also adds
an earlier raw-sample-table validator and unrelated endian fixes; only the
grid-total hunk is pinned here, which is the change that bounds this sink.

## 3. Cheapest local experiment

Two generated C drivers include verbatim slices of the pinned functions and
error enum. The only stub is `exr_coding_channel_info_t` reduced to its
`bytes_per_element` field, the sole channel member those functions read. No
EXR file, zstd frame, codec build, process, socket or network is involved.

Commands:

```
cd lab/frontier/openexr2shell/harness
./run.sh && ./check.sh
```

Three scenarios: a valid 64-byte FLOAT copy, a forged 1024-sample FLOAT grid
driving a 4096-byte copy into a 64-byte `unpacked_size`, and a valid HALF
control where `split == total == 32`. Debugger commands are in
`PROVENANCE.md`.

## 4. Rung-4 feasibility and risks

Favorable: the arithmetic, vacuous split check, sink and fix hunk are all in
verbatim pinned bytes; both gcc and clang ASan classify the write at the
pinned line; the fixed pin rejects the same inputs before the copy; plain
builds and gdb show chosen bytes landing byte-exact beyond the declared
buffer. 52 PASS / 0 FAIL on three runs; trace
`27a2a815c1ac4fbb884a9b2f754a0ab3eabaac193f8c90b0a19bf2e44337c776`.

Limits: the harness calls the two pinned functions directly. There is no EXR
header or chunk parsing, no sample-count table decoding, no ZSTD frame, no
`exr_decoding_run()` ordering, no OpenEXR or OpenImageIO build, no image
consumer, and no process, socket or wire input. The advisory's file-level
reachability, including the flat-scanline path, is a claim this wake did not
test. Chosen bytes are harness-supplied source bytes, not bytes derived from
a crafted file. No pointer or control-flow corruption was exercised.

## 5. Observations

- Rung 1: grid `[0]=1024`, one FLOAT channel, `unpacked_size=64` gives
  `split=0`, `bitSize=4096`.
- Rung 2: fixed guard returns 23 (`EXR_ERR_CORRUPT_CHUNK`) with
  `grid_total=4096` and `uncompressed_size=64`; vulnerable build has no guard
  and copies.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`,
  `WRITE of size 4096`, starting 0 bytes after a 64-byte region (4032 bytes
  past its end), at pinned `internal_zstd.c.vuln:472`.
- Rung 4: plain build reports `b64=0x5a b4095=0x5a` against a `0xa5` canary;
  gdb shows `bitSize=4096 n_hi=1024`, source `0x5a`, destination `0xa5`
  before and `0x5a` after the copy at `outPtr+64`.
- Preserved negatives: an initial clang ASan build exited 0 because it does
  not define `__SANITIZE_ADDRESS__`; buffered stdout initially hid pre-abort
  lines; a gdb breakpoint at pinned `:1393` never hit for the OOB case
  because the early return at `:1391` fires first. All three were corrected
  and the original observations are kept in `PROVENANCE.md`.

## 6. Ceiling / handoff

Ceiling measured: direct-call CODE/HARNESS rungs 1-4 only. No witness verdict,
no live decode path, no file or wire input, no pointer control, no command
execution. Rung 5 is UNKNOWN and unproven. A dedicated `openexr2shell` mind
would need to reproduce the advisory's crafted EXR against a real patched and
unpatched OpenEXR build, then measure whether the 4032-byte overwrite reaches
an allocation whose contents are usable before the process aborts. Frontier
owns no further work on this target.
