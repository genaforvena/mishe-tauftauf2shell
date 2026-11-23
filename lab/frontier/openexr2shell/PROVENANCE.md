# openexr2shell harness provenance (2026-11-23 W155)

## Source and pins

- Advisory: GHSA-98rx-qpfv-qcwv, "Missing grid-total bound in ZSTD deep decode
  causes heap out-of-bounds write in OpenEXRCore", published 2026-10-31 by
  cary-ilm, High. No CVE identifier is stated in the advisory text — UNKNOWN.
  https://github.com/AcademySoftwareFoundation/openexr/security/advisories/GHSA-98rx-qpfv-qcwv
- Claim under test: `exr_undo_zstd_v1()` derives the inverse-sort write total
  from an attacker-controlled sample-count grid but sizes `uncompressed_data`
  from the chunk leader's `unpacked_size`. The advisory reports a 692-byte
  crafted EXR and a 4032-byte overrun of a 64-byte allocation, reachable
  through flat scanline/tile APIs as well as deep ones. **The file PoC and
  the full library build were not reproduced here**; they remain claims.
- Affected 3.5.0-3.5.2; patched 3.5.3. Vulnerable pin: tag `v3.5.2`,
  `src/lib/OpenEXRCore/internal_zstd.c`. Fixed pin: tag `v3.5.3`, same path.
  Fix commit `7d7fbb1a5cf637ede04dae51123aff02d89c2b5c` (2026-10-06,
  "bound the ZSTD grid total against uncompressed_size (#2713)"). The advisory
  also states `internal_zstd.c` is byte-identical across 3.5.1, 3.5.2 and
  main; preserved as a claim. Related but distinct advisories
  GHSA-46h4-rxjp-q3rq and GHSA-6358-7h9p-8g5c were not tested.
- Byte-for-byte upstream files and the fix patch are in `src/`; their exact
  SHA-256 values are in `PINS.sha256`. Nothing under `src/` was edited.

## Verbatim slices and stubs

`harness/run.sh` generates two drivers. Each includes these **verbatim** slices
of its own pinned file under `#line` control, so ASan/gdb line numbers refer to
the pinned upstream file, not to a rendered markdown claim:

| slice | v3.5.2 (vuln) | v3.5.3 (fixed) |
| --- | --- | --- |
| `compute_sorting_lookup` | 257-295 | 271-309 |
| `sort2_4ByteChannels_tiled` | 441-480 | 455-494 |
| grid-total guard (`if (split > ...)` + grid_total loop) | absent | 1373-1394 |
| `exr_error_code_t` enum from `openexr_errors.h` | 31-69 | 31-69 |

The only C stub is `exr_coding_channel_info_t`, reduced to its `int8_t
bytes_per_element` member — the sole channel field the two pinned functions
read. For the fixed guard, a harness function declares the same five locals
that `exr_undo_zstd_v1()` has in scope at that point before the verbatim guard
lines. No EXR file, zstd stream, codec build, process, socket, wire or network
is involved.

## Commands

```
cd lab/frontier/openexr2shell/harness
./run.sh                 # 2 generated drivers, 8 binaries (gcc/clang x vuln/fixed x plain/asan)
./check.sh               # 52 assertions, normalized trace, raw evidence in evidence/
```

`check.sh` prints `PASS=52 FAIL=0 TRACE=<sha256>`; the trace excludes PID,
addresses, absolute paths and build ids. Raw ASan and plain reports live in
`harness/evidence/`.

Debugger commands (both outputs saved in `harness/evidence/`):

```
gdb -q -batch -nx -ex 'directory ../src' \
  -ex 'break internal_zstd.c.vuln:472 if bitSize > 64' -ex run \
  -ex 'printf "CHOICE bitSize=%lu n_hi=%lu readIndex=%lu writeIndex=%lu\n", ...' \
  -ex 'x/8bx inPtr' -ex 'x/8bx outPtr+64' -ex next -ex 'x/8bx outPtr+64' \
  --args ./bin-gcc-vuln-plain

gdb -q -batch -nx -ex 'directory ../src' \
  -ex 'break internal_zstd.c.fixed:1390 if grid_total > 64' -ex run \
  -ex 'printf "FIX grid_total=%lu split=%lu uncompressed_size=%lu\n", ...' \
  -ex 'bt 3' --args ./bin-gcc-fixed-plain
```

## Results

- Rung 1 (trigger): one FLOAT channel, `height=1`, forged grid `[0]=1024`,
  `unpacked_size=64`. `compute_sorting_lookup` returns `split=0` (all-FLOAT:
  no 2-byte channels), so the pre-existing `split > uncompressed_size` check
  is vacuous, while the inverse sort's `bitSize = 1024 * 4 = 4096`.
- Rung 2 (state): v3.5.3 guard returns `EXR_ERR_CORRUPT_CHUNK` (23) at pinned
  `internal_zstd.c.fixed:1390-1391` with `grid_total=4096`, `split=0`,
  `uncompressed_size=64`, before any sort call. Plain vulnerable build reports
  `CASE oob-chosen ... b64=0x5a b4095=0x5a` where a valid 64-byte copy leaves
  `0xa5` canary at those offsets.
- Rung 3 (ASan): gcc and clang both report `heap-buffer-overflow`,
  `WRITE of size 4096`, beginning 0 bytes after a 64-byte region (4032 bytes
  past its end), in `sort2_4ByteChannels_tiled` at pinned
  `internal_zstd.c.vuln:472`, the decode-direction `memcpy`.
- Rung 4 (chosen bytes): plain build writes chosen `0x5a` at `out[64]` and
  `out[4095]`, byte-exact against the `0xa5` canary; gdb shows `bitSize=4096`,
  `n_hi=1024`, source `0x5a`, destination `0xa5` before the copy and `0x5a`
  after it at `outPtr+64`.
- 52 PASS / 0 FAIL on three consecutive runs, identical trace
  `27a2a815c1ac4fbb884a9b2f754a0ab3eabaac193f8c90b0a19bf2e44337c776`.

## Negative results preserved

- First clang ASan run exited 0 and printed the plain-build canary lines:
  this clang does not define `__SANITIZE_ADDRESS__` for
  `-fsanitize=address`. Fixed with `__has_feature(address_sanitizer)` in the
  generated driver; both compilers then fault.
- First ASan runs lost their pre-abort `CASE baseline` lines because stdout
  was block-buffered when ASan aborts; fixed with `setbuf(stdout, NULL)`.
  The passing normalized trace `27a2a815...` was computed afterwards and is stable.
- A conditional gdb breakpoint at pinned `:1393` never hit for the OOB case:
  the early return at `:1391` fires first. The fixed-reject evidence was
  retaken at `:1390`.
- No pointer control, saved-return-address overwrite, command execution or
  witness replay was attempted. No OpenEXR build, EXR file or wire input was
  exercised; upstream file-level reachability stays a claim.
