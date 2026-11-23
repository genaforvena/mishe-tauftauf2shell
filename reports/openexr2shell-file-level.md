# openexr2shell — file-level ZSTD grid-total reproduction (W160, 2026-11-23)

**Result: the advisory's 692-byte EXR claim is reproduced on this host against
the real pinned OpenEXR 3.5.2 ZSTD decoder through the flat Core scanline
path.** ASan reports the 4096-byte copy attempted at the pinned sink; a
guarded allocator then measures the completed 4032-byte overwrite of a
64-byte live destination. The fixed 3.5.3 build rejects the same file with
`EXR_ERR_CORRUPT_CHUNK`, and a valid baseline leaves zero guard bytes changed.
This raises the grade from the earlier direct-call CODE/HARNESS rungs 1-4 to
**file-level rungs 1-4 with a real library and a real EXR file**. Rung 5 remains
UNKNOWN: no image-consumer process, socket, wire input, pointer/control-flow
target, command, marker side effect or witness verdict was exercised.

## Builds and inputs

- Provisioned upstream release tarballs under `lab/openexr2shell-real/src/`;
  `v3.5.2.tar.gz` sha256 `85a291b9b8563fabef1aa3f6e912d744ce1d4b9fd5a8f978eda194cd51b15ae9`,
  `v3.5.3.tar.gz` sha256 `ff1de95f4031c1c57c633e647dc97c15282d3aa3bc7fb90745f00f74de4a054f`.
- Both full-file `internal_zstd.c` pins hash-match the release trees exactly:
  3.5.2 `736dad696b6263fd5f715ccf1d93ac7104dc5f50994a769046e586af828abcea`,
  3.5.3 `0a2fe7192849399b2620c0b519db4191e82e8963665330c2f7cbd7b8696db751`.
  Exact CMake commands, tarball hashes, build rc and include/link paths:
  `lab/openexr2shell-real/BUILDLOG.md`.
- `cases/gen_baseline.cpp` and `cases/make_poc.py` are transcriptions of the
  advisory's inlined generator and mutator. Baseline: 545 bytes, sha256
  `07edcb58a3f2d63eedb5f746229f83dfc879981bf8a9d9cdf66df43a4cd6eb8e`.
  Crafted `cases/poc.exr`: 692 bytes, sha256
  `283cec0e18532c500495e71496145832d36dbfc502e44f490e09114661ab37ce`.
  It declares `unpacked_size=64` and a forged cumulative sample count of
  1024 in a raw sample table, so the grid total is 4096 bytes.
- Consumer: `harness/flat_harness.c` performs
  `exr_read_scanline_chunk_info` -> `exr_decoding_initialize` -> channel
  pointers -> `exr_decoding_choose_default_routines` -> `exr_decoding_run`
  with **no `decode_flags`**, the flat scanline shape named in the advisory.
  `harness/guarded_harness.c` adds per-allocation distinct fill bytes, a
  16 KiB inverse-filled guard and deferred frees via
  `exr_set_default_memory_routines()`.

## Commands

```
cd lab/openexr2shell-real
./harness/build.sh build-vuln-asan  src/openexr-3.5.2 bin-vuln-asan  asan
./harness/build.sh build-fixed-asan src/openexr-3.5.3 bin-fixed-asan asan
./harness/build.sh build-vuln-plain src/openexr-3.5.2 bin-vuln-plain plain
./bin-vuln-asan/gen_baseline cases/baseline.exr
python3 cases/make_poc.py cases/baseline.exr cases/poc.exr 1024 64
./bin-vuln-asan/flat_harness cases/baseline.exr
./bin-vuln-asan/flat_harness cases/poc.exr
./bin-fixed-asan/flat_harness cases/poc.exr
./bin-vuln-plain/flat_harness cases/poc.exr
./bin-vuln-plain/flat_harness cases/poc.exr prepass
./bin-vuln-plain/guarded_harness cases/baseline.exr
./bin-vuln-plain/guarded_harness cases/poc.exr
```

All stdout/stderr is preserved in `lab/openexr2shell-real/evidence/`.

## Observations

1. **Valid control, vulnerable ASan build** (`vuln-asan-flat-baseline.out`):
   `CHUNK ... unpacked=256`, `DECODE rv=0 EXR_ERR_SUCCESS`.
2. **PoC, vulnerable ASan build** (`vuln-asan-flat-poc.out`, rc 1):
   `AddressSanitizer: memcpy-param-overlap`, 4096-byte ranges
   `[0x5060000001a0,0x5060000011a0)` and
   `[0x506000000200,0x506000001200)`. Frames:
   `sort2_4ByteChannels_tiled internal_zstd.c:472` ->
   `exr_undo_zstd_v1 internal_zstd.c:1373` ->
   `internal_exr_undo_zstd :1416` -> `decompress_data compression.c:706` ->
   `exr_uncompress_chunk :786` -> `exr_decoding_run decoding.c:602`.
   Both ranges start in a 64-byte allocation from
   `internal_decode_alloc_buffer` (`coding.c:256`), one via `decoding.c:81`,
   the other via `internal_zstd.c:1335`. ASan aborts before the copy, so this
   observation proves the attempted 4096-byte copy and the two buffer sizes,
   not a completed write.
3. **PoC, fixed ASan build** (`fixed-asan-poc.out`, rc 1): no ASan report;
   `(EXR_ERR_CORRUPT_CHUNK) Unable to decompress w 13 image data 52 -> 64,
   got 256`, then `DECODE rv=23 EXR_ERR_CORRUPT_CHUNK`. The fixed build's
   grid-total guard rejects before the sort. Baseline on the fixed build is
   clean (`fixed-asan-baseline.out`, rc 0).
4. **PoC, vulnerable plain build** (`vuln-plain-poc.out`, rc 134): the decoder
   first reports `EXR_ERR_INVALID_SAMPLE_DATA` (rv=31) and then the process
   aborts with `free(): invalid pointer`. This is a separate run from the
   guarded-allocator measurement; no single execution shows both.
5. **Pre-pass control** (`vuln-plain-prepass.out`): with
   `EXR_DECODE_SAMPLE_DATA_ONLY` set, `DECODE rv=31` before pixel
   decompression; no memory error. Matches the advisory's safe 2-step claim.
6. **Guarded allocator, valid baseline** (`guarded-baseline-r{1,2,3}.out`):
   `DECODE rv=0`, `GUARD-TOTAL ... changed=0` in 3/3 runs.
7. **Guarded allocator, PoC** (`vuln-plain-guarded-poc.out` and
   `guarded-poc-r{1,2,3}.out`): destination `alloc=23 size=64` matches
   `decode.unpacked_buffer`; `GUARD-CHANGE alloc=23 size=64 changed=4032
   first=+0 expected=0xa1 actual@first=0x57`, `GUARD-TOTAL ... changed=4032`
   in 4/4 runs. `0x57` is the bitwise complement of allocation 25's fill
   (`0xa8`), i.e. the over-read crossed the end of the 64-byte scratch
   allocation into its guard and the bytes landed at the destination's first
   out-of-bounds offset. The overwrite is therefore completed, not merely
   attempted, in a live pinned 3.5.2 decode.

## C++ single-pass confirmation (same builds)

`cases/cpp_singlepass.cpp` uses `Imf::DeepScanLineInputFile::readPixels(0,0)`
with no sample-count pre-pass, matching the advisory's vulnerable C++ mode.
On the vulnerable ASan build the valid baseline prints `READPIXELS ok rv=0`,
while `cases/poc.exr` aborts with `memcpy-param-overlap` at the same pinned
`internal_zstd.c:472` (`cpp-vuln-{baseline,poc}.out`). On the fixed ASan
build the same file throws `READPIXELS exception: Unable to run decoder`
after `EXR_ERR_CORRUPT_CHUNK` and produces no ASan report
(`cpp-fixed-poc.out`). This is a second, independent real-library caller of
the same file; it is still a purpose-built consumer invoked on a local path,
not an image-application process or wire input.

## Ceiling and preserved negatives

- File input is a local EXR path handed to purpose-built C and C++ consumers.
  No OpenImageIO build, image application process, daemon, socket, port, wire,
  remote request or network probe was used. No pointer target, control-flow
  corruption, command, marker side effect, ASLR/grooming measurement or
  witness replay. Rung 5 is UNKNOWN, not a scaled-down rung 4.
- The advisory's deep-tiled, OpenImageIO and aarch64 claims were not tested.
  The `exrcheck`/`exrinfo` claims were not tested. The advisory's 4032-byte
  length and 692-byte file size were independently observed here; its
  `malloc(): invalid size (unsorted)` abort text differs from this host's
  `free(): invalid pointer`.
- Build negatives: the C consumer needed `-lstdc++`, `-ldeflate` and explicit
  static-library order; the C++ generator needed Imath config/include paths.
  The first ASan report is `memcpy-param-overlap` rather than
  `heap-buffer-overflow`; the completed write is evidenced by the guarded
  allocator, not by ASan. All intermediate link failures are preserved in
  `evidence/build-*.log`.
