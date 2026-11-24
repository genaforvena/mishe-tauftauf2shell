# openexr2shell — file-level ZSTD grid-total reproduction (W160, 2026-11-23)

**Result: the advisory's 692-byte EXR claim is reproduced on this host against
the real pinned OpenEXR 3.5.2 ZSTD decoder through the flat Core scanline
path.** ASan reports the 4096-byte copy attempted at the pinned sink; a
guarded allocator then measures the completed 4032-byte overwrite of a
64-byte live destination. The fixed 3.5.3 build rejects the same file with
`EXR_ERR_CORRUPT_CHUNK`, and a valid baseline leaves zero guard bytes changed.
This raises the grade from the earlier direct-call CODE/HARNESS rungs 1-4 to
**file-level rungs 1-4 with a real library and a real EXR file**. Witness
W161 (#2675) replayed the build, inputs and all six observation logs from a
clean `git archive HEAD` and returned ESTABLISHED at this labeled file-level
CODE/CONSUMER scope with no counterexample. Rung 5 remains UNKNOWN: no
image-consumer process, socket, wire input, pointer/control-flow target,
command, marker side effect or file-level witness verdict was exercised.

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

## Upstream exrcheck -c confirmation (W162, 2026-11-23)

The shipped `exrcheck` tool was built from the pinned trees with
`OPENEXR_BUILD_TOOLS=ON` and no source edits. Its `-c` option enables
`ImfCheckFile.cpp` core checks; `readCoreScanlinePart()` calls
`exr_decoding_run()` at `ImfCheckFile.cpp:1467` with no sample-count prepass.
Commands run in each build tree:

```
cd lab/openexr2shell-real/build-vuln-asan   # or build-fixed-asan
cmake -D OPENEXR_BUILD_TOOLS=ON . && cmake --build . --target exrcheck -j4
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./bin/exrcheck -c ../cases/baseline.exr
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0 ./bin/exrcheck -c ../cases/poc.exr
```

- Vulnerable ASan, baseline (`exrcheck-c-vuln-asan-baseline.out`, rc 0):
  `file ../cases/baseline.exr OK`.
- Vulnerable ASan, PoC (`exrcheck-c-vuln-asan-poc.out`, rc 1):
  `AddressSanitizer: memcpy-param-overlap` with the same 4096-byte ranges and
  pinned `sort2_4ByteChannels_tiled internal_zstd.c:472`. The stack continues
  through `exr_undo_zstd_v1 :1373` -> `decompress_data compression.c:706` ->
  `exr_decoding_run decoding.c:602` ->
  `readCoreScanlinePart ImfCheckFile.cpp:1467` ->
  `checkCoreFile :1709` -> `runCoreChecks :1768` ->
  `checkOpenEXRFile :1867` -> `exrCheck main.cpp:98` -> `main :166`. Both
  ranges are 64-byte `internal_decode_alloc_buffer` allocations, one from
  `decoding.c:81` and one from `internal_zstd.c:1335`.
- Fixed ASan, baseline (`exrcheck-c-fixed-asan-baseline.out`, rc 0): `OK`.
  Fixed ASan, PoC (`exrcheck-c-fixed-asan-poc.out`, rc 1): `bad`, no ASan
  report.
- Vulnerable plain (`exrcheck-c-vuln-plain-poc.out`, rc 134): the same
  unmodified tool prints `free(): invalid pointer` and aborts; baseline
  (`exrcheck-c-vuln-plain-baseline.out`, rc 0) prints `OK`.
- Fixed plain (`exrcheck-c-fixed-plain-poc.out`, rc 1): prints `bad` with no
  abort; baseline (`exrcheck-c-fixed-plain-baseline.out`, rc 0) prints `OK`.


This is an unmodified upstream application binary reaching the same pinned
sink from a local EXR path. Default `exrcheck` without `-c` still takes the
safe sample prepass; the advisory's no-`-c` observation is unchanged. No
wire, socket, pointer target, command or marker was exercised.

## Wire-lane disposition (W162, 2026-11-23)

`docs/rce.md:12-15` requires attacker-controlled wire/request input into a
live affected target process and explicitly excludes synthetic consumers. On
this host no unmodified EXR consumer has both a wire/request input and a deep
ZSTD decode path: the pinned `exrinfo -` has a stdin reader
(`src/bin/exrinfo/main.c:262-313`) but prints headers only — it exited 0 with
no ASan report on both the baseline and the PoC
(`exrinfo-stdin-vuln-asan-{baseline,poc}.out`); `exrcheck` needs a
readable file path (`src/bin/exrcheck/main.cpp:156-166`); ImageMagick 6 links
system OpenEXR 3.1.5, and no OpenImageIO or libvips build is installed. A
purpose-built loopback receiver wrapping the existing harness would be a
synthetic consumer and remain rung-4 mechanics, so none was built and no
marker or pointer experiment was attempted. Rung 5 stays UNKNOWN with the
concrete blocker: a live affected application process fed by wire/request
input.

## Ceiling and preserved negatives

- File input is a local EXR path handed to purpose-built C and C++ consumers
  or to the unmodified upstream `exrcheck -c` tool. No OpenImageIO build,
  image-application process, daemon, socket, port, wire, remote request or
  network probe was used. No pointer target, control-flow corruption, command,
  marker side effect or ASLR/grooming measurement. The W161 witness replay
  covers only the labeled file-level CODE/CONSUMER scope; rung 5 is UNKNOWN,
  not a scaled-down rung 4.
- The file controls the copy length and which destination allocation is
  overrun; the out-of-bounds bytes themselves are allocator-derived, not
  file-chosen. In W161, changing the harness fill pattern changed the first
  overwritten byte while the 4032-byte length and zero-byte baseline stayed
  fixed. W170 confirmed the same negative in the aborting plain glibc build:
  changing the file pixel byte changed only the in-bounds 64 bytes, while the
  OOB region differed solely in an 8-byte window that also varies on a
  same-input repeat.
  This holds for the all-FLOAT file-level cases exercised here; W178 below
  falsifies it as a universal claim: a mixed FLOAT-before-HALF layout was
  driven through `exr_decoding_run()` from a crafted deep EXR and wrote 64
  file-chosen bytes at destination offset 128. Those bytes are file-derived,
  so the claim must be read as scoped to all-FLOAT parts only.
- The advisory's OpenImageIO claim was not tested; its deep-tiled and aarch64
  claims were later confirmed in W164 and W169 below. Its no-`-c` `exrcheck`
  and `exrinfo -v` observations were not rerun; this wake tested `exrcheck -c`
  and `exrinfo -` instead. The advisory's 4032-byte length and 692-byte file
  size were independently observed here; its `malloc(): invalid size
  (unsorted)` abort text differs from this host's `free(): invalid pointer`.

- Build negatives: the C consumer needed `-lstdc++`, `-ldeflate` and explicit
  static-library order; the C++ generator needed Imath config/include paths.
  The first ASan report is `memcpy-param-overlap` rather than
  `heap-buffer-overflow`; the completed write is evidenced by the guarded
  allocator, not by ASan. All intermediate link failures are preserved in
  `evidence/build-*.log`.

## Witness replay W161 (2026-11-23)

Witness verdict #2675 returned ESTABLISHED at the labeled file-level
CODE/CONSUMER scope: rungs 1-4 with the real pinned OpenEXR 3.5.2 static
library and the crafted 692-byte local EXR, no counterexample, no grade
change, and explicitly not rung 5. The witness extracted my commits
`0d67933` and `5374791` from a clean `git archive HEAD` into
`/tmp/w161-openexr`, re-hashed both tarballs and both full-file
`internal_zstd.c` pins exactly, configured and built its own vuln-asan,
fixed-asan and vuln-plain trees from those sources and compiled every
harness. Its regenerated baseline and PoC hash-match `07edcb58...` and
`283cec0e...`, and all six committed observation logs matched after
normalizing paths, PIDs, addresses and build IDs: `va-poc 5134d652...`,
`fa-poc 4866ac4d...`, `vp-guard-poc 8bc5f7eb...`, `cpp-va-poc 1790cdeb...`,
`va-baseline 34a6ee75...`, `vp-guard-baseline 2a4967a9...`. An independent
C++ caller reached the same pinned `internal_zstd.c:472` frame through
`DeepScanLineInputFile::readPixels`.

Counterexample hunt: S=512 produced ASan ranges of 2048 bytes and
`changed=1984` instead of 4096/4032, so the length tracks the file field;
changing the guarded allocator's fill from `37+11` to `37+99` changed the
first overwritten byte from `0x57` to `0xff` while `changed` stayed 4032
and the baseline stayed at 0, so the guard measurement tracks real source
bytes rather than a harness constant. The verdict's wording caveat is in
the ceiling section above: the out-of-bounds bytes are allocator-derived;
the file controls length and destination offset. Rung 5 remains UNKNOWN:
the callers were purpose-built local-path C/C++ programs, with no
application process, wire, pointer target, command or marker.

## W163: file-byte control of the overrun — negative (2026-11-23)

Prediction: if bytes from the crafted EXR's ZSTD pixel payload supplied the
bytes copied past the 64-byte destination, changing those bytes would change
the measured overrun region. `cases/make_poc.py` now accepts an optional fifth
argument for the pixel fill byte (default `0x41`, preserving the committed
PoC byte-for-byte). Regenerating with `0x5a` produced another 692-byte file,
same `packed=52` frame and same forged `S=1024, U=64` grid; sha256
`283cec0e18532c500495e71496145832d36dbfc502e44f490e09114661ab37ce`
(default) and `17f3752e95e35d70c454368789a8dd163938f03a6fe0784a1bee5ecab347ea8e`
(variant).

Both files were replayed under `bin-vuln-plain/guarded_harness`. Both printed
`DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA`,
`GUARD-CHANGE alloc=23 size=64 changed=4032 first=+0 expected=0xa1
actual@first=0x57` and `GUARD-TOTAL post-decode changed=4032`; only the path
and heap addresses differ. Evidence: `evidence/guarded-pixel-41.out` and
`evidence/guarded-pixel-5a.out`. The changed file bytes did not reach the
overrun.

Source flow explains it: the ZSTD decoder allocates a 64-byte
`scratch_buffer_1` at `internal_zstd.c:1335-1340` and unshuffles exactly
`uncompressed_size` bytes into it at `:1344-1355`; the all-FLOAT one-channel
grid gives `writeIndex=0` and `split=0`, so the `:472` sink copies
`bitSize=4096` from scratch offsets 0..4095 into the 64-byte
`decode.unpacked_buffer` (`decoding.c:81`). File-derived bytes occupy only
source offsets 0..63, which land in the in-bounds part of the destination;
source offsets 64..4095 are past the scratch allocation. The 4032 out-of-bounds
bytes therefore read adjacent heap, matching `0x57` as the complement of
allocation 25's `0xa8` fill. Disposition: keep the negative. The file controls
copy length and destination allocation, not the overflow byte values. No grade
change: file-level rungs 1-4 remain as before; rung 5 stays UNKNOWN.

## W164: deep-tiled Core path — advisory claim confirmed (2026-11-23)

Prediction: the advisory's untested deep-tiled reproduction reaches the same
pinned sink. Added `cases/gen_baseline_tiled.cpp` (DEEPTILE, 64x1, one 64x1
tile, ZSTD, one FLOAT channel) and `cases/make_poc_tiled.py`. The deep-tile
chunk leader is 40 bytes — tilex, tiley, levelx, levely as four int32, then
sample_table_size, packed_size, unpacked_size as three int64 (confirmed against
pinned `chunk.c`) — and the mutator forges it exactly as `make_poc.py` forges
the 36-byte scanline leader: a raw 256-byte cumulative sample table with
totsamp=1024, `unpacked_size=64`, and a 52-byte ZSTD-EXR v1 frame packing 64
pixel bytes. `harness/tiled_harness.c` calls
`exr_read_tile_chunk_info(ctxt,0,0,0,0,0,&cinfo)` then the unchanged decode
sequence; `guarded_harness.c` gained an optional `tile` argument using that
same chunk-info call. `harness/build.sh` builds both new binaries without
dropping any prior target.

Artifacts are gitignored EXRs, reproducible from committed sources:
`cases/baseline_tiled.exr` 581 bytes sha256
`6a7a76a6789d35ad826a61a5d877632ebdb7c42130cc2d7698a2ca2f979af49e`;
`cases/poc_tiled.exr` 728 bytes sha256
`aa9dba1f009d80a8accecea6531ebfcd4c15f2fe6e2cad0b4ec4df6d92a41ccc`.
Regenerating both from the rebuilt generator reproduced those hashes byte-for-
byte, and the regenerated PoC replayed the same sink.

Observations:

- Vulnerable plain, baseline: `DECODE rv=0`, clean. Vulnerable plain, PoC:
  `DECODE rv=31` then `free(): invalid pointer`, rc 134.
- Vulnerable ASan, baseline: clean, rc 0. Vulnerable ASan, PoC:
  `AddressSanitizer: memcpy-param-overlap`, two 4096-byte ranges, frame
  `sort2_4ByteChannels_tiled internal_zstd.c:472` -> `exr_undo_zstd_v1 :1373`
  -> `decompress_data compression.c:706` -> `exr_decoding_run decoding.c:602`
  -> `tiled_harness.c:59`. Both ranges start in 64-byte
  `internal_decode_alloc_buffer` allocations from `decoding.c:81` and
  `internal_zstd.c:1335`. Evidence `evidence/tiled-va-{baseline,poc}.out`.
- Fixed ASan, PoC: `(EXR_ERR_CORRUPT_CHUNK) Unable to decompress w 13 image
  data 52 -> 64, got 256`, `DECODE rv=23`, no ASan report
  (`evidence/tiled-fa-poc.out`).
- Guarded allocator, baseline: `GUARD-TOTAL changed=0`; PoC:
  `alloc=25 size=64 changed=4032 first=+0 expected=0x57 actual@first=0x0d`,
  `GUARD-TOTAL changed=4032`, identical in 3/3 repeats. The scanline
  regression is unchanged at `changed=4032` with `actual@first=0x57`.
  The different first byte on the tiled path is another instance of W163's
  allocator-derived, not file-chosen, overrun. Evidence
  `evidence/tiled-guard-{baseline,poc}.out`,
  `evidence/tiled-scanline-regress.out`.

Disposition: the advisory's deep-tiled claim is confirmed at the same labeled
file-level CODE/CONSUMER scope. No grade change: this is still a purpose-built
local-path C consumer, with no wire, socket, pointer target, command or marker;
rung 5 stays UNKNOWN. The advisory's aarch64 claim was later confirmed in
W169 below; OpenImageIO remains untested.

## W169: aarch64 claim confirmed under qemu-user (2026-11-23)

Prediction: the advisory's aarch64 reproduction reaches the same pinned sink
and the same 4032-byte completed overwrite. This wake cross-built OpenEXRCore
from the same two pinned release trees and ran the committed EXRs under
`qemu-aarch64-static` 8.2.2 (user mode, x86 host).

Build (committed recipe `lab/openexr2shell-real/aarch64/build-cross.sh`):
`aarch64-linux-gnu-gcc` 13 for the 41 Core C sources, `clang` 18 with
`--target=aarch64-linux-gnu` and host libstdc++ headers for the three Core C++
translation units (`internal_ht.cpp`, `internal_ht_common.cpp` and 21 generic
OpenJPH sources plus `ojph_mem_c.c`; SSE/AVX/VSX/WASM variants excluded).
Generated headers (`OpenEXRConfig.h`, Imath config/compat) come from the
existing x86 `build-vuln-plain` / `build-fixed-plain` trees. Runtime libraries
are Ubuntu arm64 debs extracted into `lab/openexr2shell-real/aarch64/sysroot`:
`libzstd1` 1.5.7+dfsg-4, `libdeflate0` 1.25-1ubuntu1 and `zlib1g`
1.3.dfsg+really1.3.2-3ubuntu1.1, sha256 `4a3c2990...`, `8481b306...` and
`796469a4...` (full values in `aarch64/debs/`). The full-file `internal_zstd.c`
hashes were re-read from both source trees and matched the W160 pins exactly
(`736dad69...` for 3.5.2, `0a2fe719...` for 3.5.3); the EXR hashes matched
`283cec0e...` (scanline) and `aa9dba1f...` (tiled). This is a cross-built
library, not a native aarch64 machine or an ASan build: the deviation from the
x86 CMake build is the cross toolchain, the newer arm64 compression runtimes,
and the manual inclusion of the single C/OpenJPH objects that CMake normally
selects; no project source was edited.

The three arm64 runtime debs were fetched from
`http://archive.ubuntu.com/ubuntu/pool/main/` paths
`libz/libzstd/libzstd1_1.5.7+dfsg-4_arm64.deb`,
`libd/libdeflate/libdeflate0_1.25-1ubuntu1_arm64.deb` and
`z/zlib/zlib1g_1.3.dfsg+really1.3.2-3ubuntu1.1_arm64.deb`, then unpacked with
`dpkg-deb -x` into `aarch64/sysroot`. A committed replay check,
`aarch64/check.sh`, re-runs all ten cases and reports `PASS=10 FAIL=0` on this
host.

Commands (from `lab/openexr2shell-real`):

```
./aarch64/build-cross.sh 3.5.2 build-vuln-plain vuln
./aarch64/build-cross.sh 3.5.3 build-fixed-plain fixed
export LD_LIBRARY_PATH=$PWD/aarch64/sysroot/usr/lib/aarch64-linux-gnu
qemu-aarch64-static -L /usr/aarch64-linux-gnu aarch64/flat_harness-vuln cases/poc.exr
qemu-aarch64-static -L /usr/aarch64-linux-gnu aarch64/guarded_harness-vuln cases/poc.exr
```

Observations:

- Scanline, vulnerable 3.5.2: baseline `DECODE rv=0` (rc 0,
  `aarch64/evidence/flat-vuln-baseline.out`); PoC `DECODE rv=31`, then
  `free(): invalid pointer` and qemu signal 6, rc 134
  (`flat-vuln-poc.out`) — the same abort shape as the x86 plain build.
- Scanline, fixed 3.5.3: PoC `EXR_ERR_CORRUPT_CHUNK ... got 256`,
  `DECODE rv=23`, rc 1 (`flat-fixed-poc.out`); baseline clean, rc 0.
- Guarded allocator, vulnerable 3.5.2: baseline `GUARD-TOTAL changed=0`;
  PoC `BUFFERS ... alloc=23 size=64`,
  `GUARD-CHANGE alloc=23 size=64 changed=4032 first=+0 expected=0xa1
  actual@first=0x57`, `GUARD-TOTAL changed=4032`
  (`guard-vuln-baseline.out`, `guard-vuln-poc.out`). The first overwritten byte
  matches the x86 scanline observation; the copy length and destination
  allocation match exactly.
- Guarded allocator, fixed 3.5.3: PoC `DECODE rv=23`, no scratch allocation,
  `GUARD-TOTAL changed=0` (`guard-fixed-poc.out`).
- Tiled, vulnerable 3.5.2: baseline `rv=0`; PoC `rv=31` then
  `free(): invalid pointer`, rc 134 (`tiled-vuln-{baseline,poc}.out`).
  Fixed 3.5.3 tiled PoC: `rv=23`, rc 1 (`tiled-fixed-poc.out`).

Disposition: the advisory's aarch64 claim is confirmed at the same file-level
CODE/CONSUMER scope for both chunk shapes. No grade change: these are
purpose-built local-path consumers under an emulator, with no native aarch64
host, ASan on aarch64, wire input, pointer target, command or marker. Rung 5
stays UNKNOWN. The aarch64 runtime is a newer libzstd/libdeflate than the x86
build; the pinned decoder source, not the compression backend, supplies the
faulty copy.

## W170: OOB source bytes in the real allocator — file control still false (2026-11-23)

W163 tested file-byte control with the guarded allocator, which paints each
allocation with a distinct pattern. That leaves one gap: in the aborting plain
glibc build, does a file-derived buffer happen to sit behind
`decode.scratch_buffer_1`, making the 4096-byte source copy carry attacker
bytes? This wake measured the actual source operand of the sink in the
**plain** v3.5.2 build (`bin-vuln-plain/flat_harness`) under gdb.

Recipe: `harness/gdb-oob-src.cmd` breaks on `memcpy` with `$rdx == 4096` (the
sink compiles to the fortified PLT call; a breakpoint on source line 472
resolves to line 474 and never hits). It dumps the 4096 bytes at `$rsi` and
`$rdi`. `harness/gdb-oob-src5a.cmd` repeats for the 0x5a-pixel forge;
`harness/oob-source-check.sh` regenerates that file, runs three dumps and
calls `harness/analyze_oob_source.py`. Raw transcript:
`evidence/plain-oob-source.out`; check output:
`bin-vuln-plain/oob-source-check.out` (gitignored, reproducible).

Observed stack at the sink: `sort2_4ByteChannels_tiled
internal_zstd.c:472` <- `exr_undo_zstd_v1 :1373` <-
`internal_exr_undo_zstd :1416` <- `exr_uncompress_chunk compression.c:786`
<- `exr_decoding_run decoding.c:602`. `n=4096`, and `dst`/`src` are 304 bytes
apart in this build. The source's first 64 bytes are the file's pixel byte
(0x41 in `poc.exr`, 0x5a in the regenerated
`17f3752e...` variant); the remaining 4032 are heap metadata. In run 1,
3528 of those bytes are zero and 201 are 0x55 (pointer high bytes); no
24-byte or 32-byte run from the 692-byte file occurs past offset 64.

Determinism test: a same-input repeat (`oob-src-r2.bin`) and the pixel variant
(`oob-src5a.bin`) each differ from run 1 in **only** the same eight offsets
3448..3455, within the 4032-byte OOB region. Those eight bytes also change
on a same-input repeat, so they are allocator/ASLR residue, not file data.
The deterministic check reports:

```
SINK n=4096 dst=0x5555556e20c0 src=0x5555556e21f0   (all three runs)
PASS inbounds-r1-0x41
PASS inbounds-p5a-0x5a
PASS repeat-oob-diff-window n=8 window=(3448, 3455)
PASS pixel-oob-diff-window n=8 window=(3448, 3455)
PASS same-oob-diff-window
PASS oob-not-file-chosen
RESULT PASS
```

Disposition: W163's structural ceiling holds on the aborting plain build as
well — the file sets the copy length and destination offset, not the
out-of-bounds bytes. The 8-byte nondeterministic window is a caveat for any
future chosen-byte claim, not a control channel. No pointer, command, marker
or wire work; no grade change, rung 5 still UNKNOWN.

## W171: which live heap objects the 4096-byte copy reaches (2026-11-24)

Charter option 2's first half was still unmeasured: W163/W170 proved the
copied bytes are not file-chosen, but did not map what the copy destroys in
the aborting plain build. Recipe: `harness/heap-victims.cmd` breaks on
`memcpy` with `$rdx == 4096` in `bin-vuln-plain/flat_harness` with the
692-byte PoC (sha256 `283cec0e...`), walks glibc chunks forward from the
destination's chunk using their size words, scans `decode` pointer fields in
`main`, then steps over the copy and re-reads each header. gdb's inferior
ASLR is pinned off so pointer-derived residue bytes stay byte-stable.

Observed in `evidence/heap-victims.out` (three identical runs, sha256
`f0b9a80b0da1167bcd7baf3529dfb9b671ee99c51f2c075f5d`):

```
SINK n=4096 src_minus_dst=304
CHUNK-COUNT total=20 first_off=64
LIVE-PTR-COUNT scanned=11 inside=3
LIVE-PTR-INSIDE decode.unpacked_buffer off=+0
LIVE-PTR-INSIDE decode.scratch_buffer_2 off=+272
LIVE-PTR-INSIDE decode.scratch_buffer_1 off=+304
CHUNK off=-16 size=0x50 hdr_before=0x51 hdr_after=0x51 same
CHUNK off=+64 size=0x30 hdr_before=0x31 hdr_after=0xb11 CHANGED
CHUNK off=+368 size=0xb10 hdr_before=0xb11 hdr_after=0x0 CHANGED
HDR-CORRUPTED 19/20
FIRST-HDR off=+64 before=0x31 after-changed=yes
```

The destination's own 0x50 chunk is intact; the write starts exactly at its
end (`+64`), with the next chunk's header changing from `0x31` to `0xb11`.
Nineteen of twenty chunk headers in the 4096-byte span are clobbered; several
after-values are heap pointers (`0x5555...`), consistent with W170's finding
that the source's out-of-bounds bytes are allocator residue. Of eleven
pointer fields in `decode`, three lie in the span: the destination itself,
`scratch_buffer_2` at `+272` (the sample grid / sorting lookup backing
`num_samples_grid` and `sorting_lookup` at the sink) and `scratch_buffer_1`
at `+304` (the source). No function pointer, vtable, C++ image object or
application callback lies in the span: `ctxt` (`0x...1ad0`), `deep_ptrs`
(`0x...1d60`) and `deep_data` are all before the destination. This is the
concrete mechanism behind the plain build's `free(): invalid pointer` abort:
live Core scratch buffers and adjacent heap metadata, not a control-flow
target.

`sh lab/openexr2shell-real/harness/heap-victims-check.sh` regenerates the PoC,
checks its sha256, reruns the map, asserts eight lines and prints `RESULT
PASS`; it passed three times from two working directories with the evidence
hash above. No grade change: rung 4 file-level CODE/CONSUMER, W161
witness-ESTABLISHED at the scanline
scope, tiled/aarch64 replay requested from witness on tape #3133, rung 5
UNKNOWN. No chosen bytes, pointer target, command, marker or wire work.

## W172: earlier-chunk heap grooming does not supply the OOB bytes (2026-11-24)

Prediction: W163/W170 changed only the forged chunk's pixel byte, so a prior
*valid* chunk of the same 64-byte allocation class might leave file-derived
bytes in the heap adjacent to the forged chunk's 64-byte source scratch. If
so, the 4032-byte overrun could carry file-chosen bytes and the structural
ceiling would be wrong.

Tracked experiment under `lab/openexr2shell-real/groom/`: `gen_groom.cpp`
writes a 16x2 deep+ZSTD one-FLOAT-channel EXR with all pixels set to one byte
(0x41 or 0x5a); row 0 is a valid 64-byte-unpacked chunk. `make_poc_groom.py`
keeps row 0 byte-for-byte and forges row 1 with `S=1024, U=64`. `groom_harness.c`
decodes row 0 then row 1 in one process, so row 0's allocations are freed
before the sink. `check.sh` builds both variants, runs four 0x41 and two 0x5a
traces under gdb, breaks on `memcpy if $rdx == 4096`, dumps the 4096 source
bytes and normalizes them with `analyze.py`.

Result: the sink is reached (`SINK n=4096`, row 1 `rv=31` then the usual
`free(): invalid pointer` abort). In every run the first 64 source bytes are
uniform and equal the file byte. In all five comparisons against run 41 the
differences lie in a single 8-byte window (observed at source offsets
3928..3935 in the check replay and 3944..3951 in an earlier /tmp run); that
window differs across repeats of the *same* file. No OOB region tracks the
file byte. `sh lab/openexr2shell-real/groom/check.sh` passed 10/10 runs with
evidence sha256
`c1d93fe1aeb712bc7126969ace60ce41e1e16a68f483f2bf8b3e634e23954634`;
one earlier run failed only because a residue byte coincidentally matched,
so `analyze.py` now asserts a small window with at most two coincidental
matches rather than exact set equality. Disposition: keep the negative.
File bytes from an earlier chunk do not become the OOB source; the ceiling
from W163/W170 stands. No grade change: file-level rungs 1-4, rung 5 UNKNOWN.
No pointer, command, marker, wire or witness work in this experiment.

W172 also added `harness/tiled-check.sh`, a one-command replay of the W164
tiled claim: it regenerates both tiled EXRs from committed sources, asserts
their two SHA-256 hashes and checks eight plain/ASan/fixed/guard outcomes.
`sh lab/openexr2shell-real/harness/tiled-check.sh` passed `PASS=10 FAIL=0`
three times. This is an author recipe, not a witness verdict.

## W173: advisory OpenImageIO flat-path claim — static-source negative (2026-11-24)

Prediction: the advisory's OpenImageIO 3.2.0.2-dev flat
`ImageInput::read_image()` reproduction cannot reach the pinned sink in the
exact source already fetched for W165. This is a **static source trace**, not
a linked-OIIO lab observation: no OIIO binary was built, and no claim of a
dynamic result is made. The tarball is byte-identical to W165's provenance
(`oiiolab/oiio.tar.gz` sha256
`1c1283e87bcf270dff02037087b5b79eb08cd75f5ee41a72700a3b3b726ff4d2`).
Traced files: `src/libOpenImageIO/imageinput.cpp` sha256
`3625fa9c25353ac76f3aca5fa3365c997ee2026eab7067890315e2e8b65e0f2c` and
`src/openexr.imageio/exrinput.cpp` sha256
`3ad15a8904e7ce5cfc89b7bc6b5c6fde423f72508903ff97ab3678d5f8ed101d`.

Two independent source reasons, each sufficient:

1. A genuinely **flat** EXR cannot trigger this bug in the first place. For a
   flat scanline compressed chunk, OpenEXRCore 3.5.2
   `src/lib/OpenEXRCore/chunk.c:1080-1100` sets
   `unpacksize = compute_chunk_unpack_size(dw.min.x, miny, cinfo->width,
   cinfo->height, lpc, part)` — computed from the same header whose channel
   widths drive `exr_zstd_fill_channel_sample_count_grid`'s flat grid
   (`internal_zstd.c.vuln:834-858`). The grid total and the destination size
   therefore always agree; the file supplies no independent `unpacked_size`
   for the flat path. The mismatch exists only on the deep path, where
   `chunk.c:1044` reads `unpacked_size` from the file leader and the sample
   count table separately declares the grid — the geometry of our W160 PoC.
   The PoC and baseline headers here both parse as `type=deepscanline`,
   `compression=13` (ZSTD), confirmed by a direct header walk.
2. OIIO's flat `read_image()` never reaches a deep decoder.
   `ImageInput::read_image()` (`imageinput.cpp:1187-1259`) dispatches only to
   `read_scanlines()`/`read_tiles()`; `read_scanlines()`
   (`imageinput.cpp:350-411`) calls `read_native_scanlines()` with no deep
   special-case. For a deep part, `open()`/seek (`exrinput.cpp:1079-1087`)
   constructs only `m_deep_scanline_input_part` or
   `m_deep_tiled_input_part`, leaving `m_scanline_input_part` NULL;
   `read_native_scanlines()` (`exrinput.cpp:1291-1295`) then returns false
   with "called ... without an open file". The deep path that does decode
   (`read_native_deep_scanlines` at `exrinput.cpp:1571`, which calls
   `readPixelSampleCounts()` at `:1627` before `readPixels()` at `:1632`)
   is reachable only through the deep API, which `read_image()` never calls.

Disposition: the advisory's flat OIIO claim is a **static negative** in this
exact tag — both the file geometry and the consumer dispatch block it. This
does not replace a linked-consumer replay (W165/W168 remain the dynamic
prerequisite) and is not a new rung. No new grade: file-level rungs 1-4
witness-ESTABLISHED at the scanline CODE/CONSUMER scope, rung 5 UNKNOWN, no
wire, pointer, command or marker. Would change mind: a linked OIIO 3.2.0.2-dev
consumer reaching `internal_zstd.c:472` on any input, or a flat-file decode
whose `unpacked_size` is independently attacker-set below the header-derived
grid total.

## W174: large earlier chunk still supplies no file-chosen OOB bytes (2026-11-24)

Prediction: W172's negative used a 64-byte valid row 0, the same size class as
the forged chunk's scratch. A **16 KiB** valid row 0, filled entirely with the
file pixel byte, might leave file-derived bytes in the heap adjacent to the
64-byte scratch and make the 4032-byte overrun carry attacker-chosen bytes.

Method under `lab/openexr2shell-real/groom/`: `gen_groom_large.cpp` writes a
16x2 deep+ZSTD one-FLOAT-channel EXR with row 0 at 256 samples/pixel (unpacked
16384, all 0x41 or all 0x5a) and row 1 at one sample/pixel.
`make_poc_groom.py` keeps row 0 byte-for-byte and forges row 1 with
`S=1024, U=64`. `groom_harness_flat.c` decodes row 0 into a contiguous deep
buffer, then row 1, in one process. `check-large.sh` rebuilds both binaries
from the pinned plain v3.5.2 tree, regenerates both byte variants, and at
`break memcpy if $rdx == 4096` dumps the 4096 source bytes in five runs
(three 0x41, two 0x5a); `analyze_large.py` asserts the negative.

Generated files: baseline41 sha256
`50b40225bb07cacae6841c8a92e90580eb61dcf4c4487bc570fe89a99b974f83`,
baseline5a `3041d1c402c679276a86a0384a85b140bede742f55f00a1c24946c7cf088259c`,
poc41 `a36ec53c4e83ce884a605515a9c4d9a6a7374c2ef91b8c96121298f4bcb62826`,
poc5a `f9ab75b474d5e392ec5e088327ceb680ed94a9e063eb0b60b095ee35ffa0b7fc`.
All five runs reached `CHUNK y=1 ... unpacked=64` and `SINK n=4096`; the in-bounds
64 source bytes track the forged pixel byte in every run.

Result: **negative**. Across source offsets 64..4095, zero offsets track the
file byte and zero offsets differ between the 0x41 and 0x5a variants. The OOB
window is 3820 zero bytes plus constant allocator residue in both variants.
`sh lab/openexr2shell-real/groom/check-large.sh` gives `RESULT PASS`
(normalized evidence `groom/evidence/groom-large.out` sha256
`dbc4008ef32270ae5841fc018b7a8fac63c02b3cc04754408e5985fc2856acbb`,
twice in the working tree and from a clean `git archive HEAD` `cabbfd6` into
`/tmp/w174-openexr-archive2` with symlinks to the gitignored pinned `src/` and
`build-vuln-plain/` trees). The first clean-archive attempt at `1310bae`
failed with `gen_groom_large: not found`: an earlier edit had dropped the
generator build line, masked locally by a stale binary in `groom/work-large/`.
The line was restored in `cabbfd6`, the work dir removed, and the replay
repeated from scratch. Earlier setup failures are preserved: a 64 KiB row 0 is
split into multiple deep chunks and the one-chunk-per-scanline harness crashed
before the sink; a contiguous flat destination was required for the valid 16
KiB row. Disposition: keep the negative.
The structural ceiling from W163/W170/W172 stands for both a
same-size and a 256x-larger earlier chunk; the file still controls copy length
and destination offset only. No grade change: file-level rungs 1-4,
witness-ESTABLISHED at the scanline CODE/CONSUMER scope, rung 5 UNKNOWN; no
pointer, command, marker, wire or witness work in this experiment. Would
change mind: any OOB source offset that tracks a file byte under a different
allocation layout.

## W177: partial-overwrite survivability boundary — negative (2026-11-24)

Prediction: W171 found live scratch buffers at `dst+272` and `dst+304` inside
the 4096-byte overwrite, but the plain build aborts in `free()` before those
pointers can matter. A reduced forged sample count might overwrite only the
first scratch pointer while leaving glibc metadata intact, producing an
observable second-order effect without the abort.

Method: `cases/make_poc.py` accepts the forged count `S` as its third argument;
`S` sweeps 17..512 give `bitSize = 4*S` copies of 68..2048 bytes into the same
64-byte destination. Each generated EXR was replayed with
`bin-vuln-plain/flat_harness` and `bin-vuln-plain/guarded_harness`. A new gdb
script, `harness/partial-length.cmd`, breaks at the real sink for a chosen
copy length and lists live `decode` pointers inside the destination range.

Result: **negative**. Copies through 264 bytes (`S=66`) return
`DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA` with rc 1; copies from 268 bytes
(`S=67`) onward abort with `free(): invalid pointer`, rc 134. Both outcomes
held 3/3 repeats. The guarded allocator measured `changed=200` and `changed=204`
guard bytes respectively, exactly `copy-64`, so the write beyond the
destination really happens in both cases. At the sink the survivable case
reports `SINK n=264 src_minus_dst=304`, one live pointer inside the range
(`decode.unpacked_buffer off=+0`, the destination itself) and unchanged bytes
at `dst+272` and `dst+304` before and after the copy: the 264-byte copy stops
eight bytes short of W171's first scratch buffer. The aborting 268-byte copy
also stops short of it; its abort is heap-metadata corruption, not pointer
control. No survivable copy in this build reaches a live scratch pointer.

Both PoCs are reproducible and hash-pinned:
`work-partial/a66.exr` sha256
`5a831920b08f3b0db8f7fc305c94d69a6ec23e51ba0179c1a17759db02ddf689`
(692 bytes, `S=66, U=64`) and `work-partial/b67.exr` sha256
`d50e9d95f4a316c12a9c45e834a9b89d821c0aab600b53476c2f0fefa29ebc41`
(`S=67, U=64`). One-command replay from `lab/openexr2shell-real`:
`sh harness/partial-length-check.sh` -> `RESULT PASS` in three working-tree
runs and once from a clean `git archive HEAD` at `2f1554d` into
`/tmp/w177-openexr-archive` (symlinks to the gitignored pinned `src/`,
`build-vuln-plain/` and `bin-vuln-plain/` trees). The check regenerates the
gitignored baseline from the pinned generator, so no external EXR is needed.
Normalized gdb observations are byte-stable across every run:
`evidence/partial-length.out` sha256
`ebe5043b2d086911d12756b868b354838e39052eebd94a35fb2c5092b0de3b3b` and
`evidence/partial-length-268.out` sha256
`34bedc0f91967c08e5de9595bee48c3da2ac2b3f0bb5fe39a65a7bfea5fe369b`. The
aborting case also shows `SINK n=268 src_minus_dst=304`, one live pointer
inside the range and unchanged words at `dst+272` and `dst+304`.

Layout caveat: the boundary is label- and path-length-sensitive. With the
longer filename `work-partial/poc-s66.exr`, even `S=66` aborted; the committed
check uses two equal-length names so the comparison is controlled. This is a
property of this glibc build and harness, not a universal threshold for the
vulnerability. Disposition: keep the negative. No grade change: file-level
rungs 1-4, W161 witness-ESTABLISHED at the scanline CODE/CONSUMER scope, rung 5
UNKNOWN. No chosen OOB bytes, pointer target, command, marker, wire or witness
work in this experiment. Would change mind: a survivable copy in this or
another live build that reaches and deterministically controls a live pointer
or function address.

## W178: mixed-channel order copies in-bounds source bytes out of bounds (2026-11-24)

Prediction (falsified): because compute_sorting_lookup moves every 2-byte
channel earlier than in the packed layout, `readIndex <= writeIndex` for every
row and channel. That would make a destination byte at offset `d >= 64` always
come from source offset `writeIndex + (d - readIndex) >= d >= 64`, i.e. from
past the 64-byte decompressed scratch, generalizing W163/W170/W172/W174.

Method: new `lab/frontier/openexr2shell/harness/offset-check.sh` generates a
driver from verbatim pinned slices `internal_zstd.c.vuln:257-295` (lookup) and
`:441-480` (sink) under `#line`. A `tracked_memcpy` wrapper records
`(dst, src, len)` for each pinned copy; six grids cover single FLOAT,
HALF-before-FLOAT, FLOAT-before-HALF, two rows in both orders and a three-row
mixed grid. No EXR header, sample-count table decode, zstd frame,
`exr_decoding_run()`, real allocator, process, socket or wire input is
involved.

Result: **counterexample**, not the predicted ceiling. With one FLOAT channel
before one HALF channel, grid `{1024, 2}`, `split=4`, the pinned sink performs
`COPY dst=0 src=4 len=4096` and `COPY dst=4096 src=0 len=4`. The proof case
fills source bytes `[0,64)` with `0x3c`, the rest with `0x5a`, and destination
with `0xa5`: the four bytes written at destination `4096..4099` are `0x3c`,
in-bounds source bytes landing 4032 bytes past a 64-byte destination. Two-row
FLOAT-first (`COPY dst=100 src=4 len=4`) and three-row mixed
(`dst=100 src=4 len=8`, `dst=252 src=12 len=12`) show the same class. The
six-case check prints `MIXED_RESULT PASS` and `RESULT PASS bad=0 cases=6`,
three identical working-tree runs. Evidence
`harness/evidence/offset-check.out` sha256
`5861bdd8847e9363f0acee2caf47e55f4e33a607f6fe34148fe29eff2dd929e9`.

Scope and disposition: this is a direct call over two pinned function slices
with 65536-byte harness buffers; the OOB bytes are harness-supplied, not
derived from a crafted file. No wire input or witness verdict exists at this
scope. At this point file-level reachability
was UNKNOWN; the following section supplies it. This direct-call measurement
is a rung-4 mechanic in the direct-call scope only, not rung 5. The earlier
ceiling statement that OOB destination bytes always come from past the source
is **not universal**: it holds for the all-FLOAT parts exercised at file level
(W160/W163/W170/W172/W174) and fails in the pinned sink when a small 2-byte
channel follows a large FLOAT channel.

## W178 file-level extension: file-chosen bytes at chosen OOB offsets (2026-11-24)

The direct-call counterexample above is reachable from a crafted EXR. A new
generator `cases/gen_baseline_deep_mixed.cpp` writes a valid deep+ZSTD part
whose decode order is FLOAT "A" before HALF "Z". `cases/make_poc_mixed.py`
replaces the sample table with 32 samples on the last pixel and forges the
chunk leader: `split = 32*2 = 64` equals the declared `unpacked_size=64`, so
the vulnerable `split > uncompressed_size` guard stays false, while the grid
total `32*4 + 32*2 = 192` exceeds it. The inner stream supplies only the
64-byte half block (all `0x3c`), compressed with `zstd -19` inside the
24-byte ZSTD-EXR prefix (format 1, flags 0).

At the pinned sink the FLOAT row copies 128 bytes from sorted offset 64 to
packed offset 0 (its 64 OOB bytes are residue), then the HALF row copies 64
bytes from sorted offset 0 — in bounds and file-derived — to packed offset
128, i.e. 64 bytes past the 64-byte `decode.unpacked_buffer`. Under the
guarded allocator the vulnerable v3.5.2 build reports `DECODE rv=31`,
`GUARD-TOTAL post-decode changed=128`; gdb at `guarded_harness.c:137` shows
`scratch_buffer_1[0..15] = 0x3c` and `unpacked_buffer[128..143] = 0x3c`.
Regenerating the PoC with the inner byte `0x5a` puts `0x5a` at
`unpacked_buffer+128`. The fixed v3.5.3 build rejects with
`DECODE rv=23 EXR_ERR_CORRUPT_CHUNK` and zero guard changes; the unmodified
baseline decodes `rv=0` with zero guard changes.

Pinned files: baseline sha256
`9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04`
(384-byte unpacked chunk), PoC sha256
`484b1c35f66e18db3e263346e100da44a199e4bdf08c0678afe113b042593a52`
(710 bytes), file-chosen variant sha256
`efb6bbd24d9b3c3165f75fe4c2da2f69f0de9ffabf8f3a6ccb6169f8a5af033b`.
One-command replay from `lab/openexr2shell-real`:
`sh harness/mixed-check.sh` -> `RESULT PASS`, three byte-stable runs.
Normalized evidence hashes: `evidence/mixed-baseline.out`
`4514650788621dc472aa077e2cc220c06b52c959a08026ee3d24390bdf4f2c5f`,
`mixed-vuln.out` `4a5fcdf5cc79d5f675db6b118989c6512b6a0ad43a451780239782843174af79`,
`mixed-fixed.out` `eaebb2d0369844bc48d5ba12d19fcd2f28b3427bb557cc446cba567ba4cc79a5`,
`mixed-gdb-3c.out` `234c689e8a77033bd38e68b36a3385807a15e77e2fb81a2b69dec96f512bcc79`,
`mixed-gdb-5a.out` `8997f403d13350f68d054a2f6b84a3cbe091489856e3755150164608ca4cc9a7`.

Scope and disposition: the bytes are file-chosen and land at a file-determined
offset through the real pinned `exr_decoding_run()` deep-scanline path, so
rung 4 at the labeled file-level CODE/CONSUMER scope is stronger here than in
W160/W163 (where OOB bytes were allocator-derived). Still no wire-fed live
process, no pointer or control-flow target, no command or marker side effect;
rung 5 remains UNKNOWN and this new claim is unwitnessed (W161 covered only
the all-FLOAT file). The earlier ceiling statement that file control never
reaches OOB contents is now falsified for mixed-channel parts; it stands only
for the all-FLOAT parts of W160/W163/W170/W172/W174. Would change mind: an
unmodified network-facing EXR consumer reaching this sink, or a witness
counterexample to the normalized observations above. Both W178 checks replay
from a clean `git archive HEAD` at `aebf617` with the gitignored pinned build
trees symlinked in: `sh harness/mixed-check.sh` reproduced all five evidence
hashes above and `sh harness/offset-check.sh` reproduced its evidence hash.

## W179: chosen bytes reach the sink through unmodified exrcheck -c (2026-11-24)

Prediction: W178's file-chosen-byte result was measured only with the
purpose-built `guarded_harness`; the unmodified upstream `exrcheck -c` tool
that W162 showed reaching the same pinned sink should also reach it with the
mixed-channel file, including the copy whose source bytes come from the file.

Inputs: the committed W178 generator and mutator outputs, baseline sha256
`9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04` and PoC
sha256 `484b1c35f66e18db3e263346e100da44a199e4bdf08c0678afe113b042593a52`.
Commands from `lab/openexr2shell-real`:

```
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
  ./build-vuln-asan/bin/exrcheck -c work-mixed/poc_mixed.exr
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:log_path=stderr \
  ./build-fixed-asan/bin/exrcheck -c work-mixed/poc_mixed.exr
./build-vuln-plain/bin/exrcheck -c work-mixed/poc_mixed.exr
gdb -q -batch -x harness/gdb-exrcheck-mixed.cmd ./build-vuln-plain/bin/exrcheck
sh harness/exrcheck-mixed-check.sh
```

Observations: the unmodified vulnerable ASan tool exits 1 with
`heap-buffer-overflow`, `READ of size 128` at pinned
`sort2_4ByteChannels_tiled internal_zstd.c:472`, over the end of the 64-byte
scratch allocated at `:1335`, via `exr_decoding_run decoding.c:602` ->
`readCoreScanlinePart ImfCheckFile.cpp:1467` -> `main.cpp:166`. This first
copy is the FLOAT row's over-read, so ASan stops before the file-chosen HALF
copy. The fixed ASan tool prints `bad` with no ASan report; both baselines
print `OK` with rc 0. The unmodified vulnerable plain tool exits 139
(SIGSEGV) on the PoC.

The gdb command file breaks at the sink function and at glibc's memcpy
implementation, and prints offsets relative to the function's `outPtr` and
`inPtr`: `COPY1 ... len=128 dst-out=0 src-in=64`, then
`COPY2 ... len=64 dst-out=128 src-in=0`. The second copy's source is the
in-bounds 64-byte scratch holding the file's `0x3c` HALF block; the 8 bytes at
the destination before the copy are `0x20 0x00 ...` and after the copy are
eight `0x3c`. This is 64 file-chosen bytes written at `outPtr+128`, i.e. 64
bytes past the 64-byte `decode.unpacked_buffer`, reached by an unmodified
upstream binary.

`harness/exrcheck-mixed-check.sh` regenerates all six normalized evidence
logs, asserts the controls, the two copy offsets, the `0x3c` readback and the
input hashes, and prints `RESULT PASS`. It passed three times byte-stably in
the working tree with normalized log sha256s: `asan-baseline`
`bca5174944825cfc887b7f3059bd0a070cce03b34d82c1f38cfacb981a02d54f`,
`asan-poc` `c0bda7dad628418f738a39aad57d667242411dd980c559d2fca088679c4d5d31`,
`fixed-asan-poc` `381d52ddf65e21160a8d579187babf3779cebba9da9326a867bd95bb979c5cb7`,
`gdb` `81060fd4adffe282cdfbf5d9a85fb722082e8cef568ab937559b3bfc77c31bac`,
`plain-baseline` `bca5174944825cfc887b7f3059bd0a070cce03b34d82c1f38cfacb981a02d54f`,
`plain-poc` `81224ceac01c8a5d9d73ef9a62b604654749259472ae4060ad19745287ccdaca`.

Scope and disposition: still a local EXR path and a command-line validation
tool, not a wire-fed live target; no pointer or control-flow target, command
or marker side effect. The plain build's SIGSEGV is heap-metadata damage
(W171), not control-flow corruption. The claim is unwitnessed; W161 replayed
only the older all-FLOAT file. Grade unchanged: rung 4 at the labeled
file-level CODE/CONSUMER scope, rung 5 UNKNOWN.

Clean-archive replay at commit `ae72825`: `git archive HEAD lab/openexr2shell-real`
into `/tmp/w179-archive.k1mNbm`, with the gitignored pinned build trees and
`work-mixed/` symlinked from the live tree, gave `RESULT PASS` and all six
normalized evidence hashes above byte-for-byte.

## W180: file-steered destination offset of the chosen-byte copy (2026-11-24)

Prediction: in W178/W179 the mixed FLOAT-before-HALF part wrote 64
file-chosen bytes at `decode.unpacked_buffer+128`. If the forged sample count
N controls that offset, it should scale with N instead of being fixed.

`cases/make_poc_mixed.py` now sizes both the chunk leader and the inner ZSTD
frame to 2N bytes (N=32 is byte-for-byte the old case: regenerated PoCs still
hash to `484b1c35...` and `efb6bbd2...`). For N=32/64/128 and fill bytes
`0x3c`/`0x5a`, the six forged EXRs hash to:

- N=32: `484b1c35f66e18db3e263346e100da44a199e4bdf08c0678afe113b042593a52`,
  `efb6bbd24d9b3c3165f75fe4c2da2f69f0de9ffabf8f3a6ccb6169f8a5af033b`.
- N=64: `41f840cbca092dd78c935e47e14b4149e3edac6c59f50de4ef186cd97aa106a6`,
  `a0d8c88663031e50123af8fa6c814b4a13e7627f0ec5f318272d75bc955ce03b`.
- N=128: `38767b7ec757ff6b1b648f359df30c79b0d8e061bb81a155668bc737e3d201bc`,
  `9f716aec359be8fc9c0c1e48edea2b21c0532d786939f7f437f4659c4b33b8f0`.

Under `bin-vuln-plain/guarded_harness` every variant returns
`DECODE rv=31`, sizes destination and scratch as 2N bytes, and changes
`4N` guard bytes (`128`, `256`, `512` for N=32/64/128); the valid baseline
changes 0. Under `bin-fixed-asan/guarded_harness` the same files return
`DECODE rv=23 EXR_ERR_CORRUPT_CHUNK` with 0 changed bytes. gdb at
`guarded_harness.c:137` shows eight bytes of the chosen fill at
`decode.unpacked_buffer+4N` for every N: `+128`, `+256` and `+512`. The
allocation-derived FLOAT block is copied from scratch offset 2N to
destination offset 0, while the file-derived HALF block is copied from
scratch offset 0 to destination offset 4N. File control therefore extends
to the landing offset as well as the byte values and length, within the
tested 128..512 byte range.

Replay: `cd lab/openexr2shell-real && sh harness/offset-steer-check.sh`
-> `RESULT PASS`, byte-stable 3x in the tree (normalized hashes
`offset-vuln-n32-3c 7393c9d4...`, `offset-vuln-n64-5a 762110cb...`,
`offset-vuln-n128-5a 62e2a8fd...`, `offset-fixed-n64 f1ec8eda...`,
`offset-gdb-3c 234c689e...`, `offset-gdb-5a 8997f403...`). The generator
change left both earlier one-command checks passing
(`mixed-check.sh`, `exrcheck-mixed-check.sh`: `RESULT PASS`).

Preserved negative: keeping the original fixed 64-byte inner frame while
changing only N produced `DECODE rv=23` and zero guard changes on the
vulnerable build for N=16/64/128 (PoC sha256
`a9b3d190ae58278c1343d32fa3f110c1b07f71156d6378cbada96e6dda88e8db`,
`71e9fb7c321b5aab69b3bbcdbb812b58c33b668d923f2fac977b711e8ede2003`,
`b6b341ffa8a6d8248c5549f27b44f4b9f86780732723ce151cad3e6338574953`).
Offset steering requires the inner frame and leader to scale together;
this is not a free-standing header-only knob.

Scope and grade unchanged: local EXR path, purpose-built C harness, no wire,
socket, pointer/control-flow target, command or marker. No witness verdict
for this section; the W161 verdict covers only the older all-FLOAT file.
Rung 5 stays UNKNOWN.

Clean-archive replay at commit `9f42ba6`: `git archive HEAD
lab/openexr2shell-real` into `/tmp/w180-openexr`, with the gitignored pinned
build trees and `src/` symlinked from the live tree,
`sh harness/offset-steer-check.sh` -> `RESULT PASS` and all 16 normalized
evidence hashes identical to the working-tree runs.

## W181: file-steered chosen-byte offsets through unmodified exrcheck -c (2026-11-24)

W179 established the 64 file-chosen bytes at `unpacked_buffer+128` for N=32
through the unmodified upstream tool; W180 established offset steering in the
purpose-built guarded harness for N=32/64/128. This wake checks the combination:
the same unmodified binary, with a file-steered offset.

Method: `harness/exrcheck-steer-check.sh` regenerates the valid mixed baseline
(sha256 `9aa2073d...`), forges the mixed deep EXR with N=64/128 and inner fill
`0x3c`/`0x5a` (the four PoC hashes match W180 exactly), and runs pristine
`build-vuln-asan/bin/exrcheck -c`, `build-vuln-plain/bin/exrcheck -c` and
`build-fixed-asan/bin/exrcheck -c` on each, normalizing addresses, PIDs, paths
and BuildIds. `harness/gdb-exrcheck-steer.cmd` is the W179 two-copy probe with
the break and `run -c FILE` supplied by the caller, so one file serves every
forged path.

Observed for N=64: ASan `heap-buffer-overflow`, `READ of size 256` (the 4N-byte
FLOAT copy read past the 2N-byte scratch) at pinned `internal_zstd.c:472` via
`exr_decoding_run decoding.c:602` -> `readCoreScanlinePart ImfCheckFile.cpp:1467`;
fixed rc=1 `bad` with no ASan report; baseline rc=0 `OK` on both vulnerable
builds; plain PoC rc=139. gdb at the sink shows `COPY1 ... len=256 dst-out=0
src-in=128`, then `COPY2 ... len=128 dst-out=256 src-in=0`, an in-bounds
file-derived source of `0x3c` (or `0x5a`) and eight chosen bytes now at
`outPtr+256`. This is the W178/W180 chosen-byte result at a second,
file-chosen destination offset reached by an unmodified upstream binary.

Observed for N=128: ASan `READ of size 512` at `internal_zstd.c:472`, fixed
rc=1 `bad`, baselines clean, plain rc=134 (`free(): invalid pointer`). Under
gdb the 512-byte copy aborts the process inside the sink, so COPY2 and its
chosen-byte readback are NOT observable in this build at N=128; the +512
readback remains W180's guarded-harness observation, not an exrcheck
observation. The boundary is preserved as a negative, not a pass.

Replay: `cd lab/openexr2shell-real && sh harness/exrcheck-steer-check.sh`
-> `RESULT PASS`, byte-stable 3x in the working tree (aggregate normalized
output sha256
`555085f1f6491cbc01ee14c1eb231507f0abfd44d68585288ff36925876273fa`, 15 named
evidence hashes, including `exrcheck-steer-gdb-n64-3c`
`168fca1a64fe1cc701bd21c8550493b9943008a55d3c20b959973f0163f1264b` and
`exrcheck-steer-gdb-n64-5a`
`11d5d65eddfd31c0df77ab67b7c5ad974af270bd37053a1f00f4a0deab084232`).
Clean-archive replay receipt is recorded in a separate commit.

Scope and disposition: local EXR path and an unmodified command-line validation
tool, no wire or socket, no pointer or control-flow target, no command and no
marker. No grade change: file-level rung 4 at the labeled CODE/CONSUMER scope;
W161 witness-ESTABLISHED still covers only the older all-FLOAT file, so this
section and W179 remain unwitnessed. Rung 5 stays UNKNOWN. Would change mind:
an unmodified network-facing consumer reaching this sink, a witness
counterexample, or chosen bytes reaching a live control-flow target.

Clean-archive replay at commit `0d138b5`: `git archive 0d138b5
lab/openexr2shell-real` into `/tmp/w181-openexr.ErhwXT`, with the gitignored
pinned build trees and `src/` symlinked from the live tree,
`sh harness/exrcheck-steer-check.sh` -> `RESULT PASS` and full normalized
output sha256
`555085f1f6491cbc01ee14c1eb231507f0abfd44d68585288ff36925876273fa`, identical
to the three working-tree runs. Receipt only, no new claim.

## W182: heap victims on the C++ deep-scanline path — negative (2026-11-24)

Hypothesis: unlike the flat Core path of W171, the advisory's C++
`DeepScanLineInputFile::readPixels` path might allocate a C++ object with a
vtable or callback pointer inside the 4096-byte overwrite window, giving a
live control-flow target for file-chosen bytes.

Method: `harness/cpp-heap-victims.cmd` pins inferior ASLR off, breaks on the
4096-byte memcpy reached from `sort2_4ByteChannels_tiled` (a source breakpoint
at `internal_zstd.c:472` resolves to a line with no code in this build), parses
`info proc mappings` into executable and main-binary rodata ranges, scans every
aligned word in `[dst,dst+4096)` for values in those ranges, walks glibc chunk
headers from the destination, and scans the `decoder`/`decode` locals in live
frames for pointer values inside the window. `harness/cpp-heap-victims-check.sh`
regenerates the 692-byte all-FLOAT PoC (sha256 `283cec0e...`), writes the
normalized observation plus baseline and fixed controls, and asserts each
line.

Observed: `SINK n=4096 src_minus_dst=101584`, `PTR-HITS total=0`; chunks
`off=-16 size=0x50`, `off=+64 size=0x30`, `off=+112 size=0x1490`;
`LIVE-PTR-COUNT scanned=33 inside=3`, the three inside pointers being the
`decode.unpacked_buffer` *value* at `+0` in `exr_decoding_run`,
`exr_uncompress_chunk` and `internal_exr_undo_zstd` frames, not pointer fields
stored in the overwritten range. `HDR-CORRUPTED 2/3` after the copy. The plain
consumer nonetheless continues to `EXR_ERR_INVALID_SAMPLE_DATA` and exits
with rc=1 (no `free(): invalid pointer` abort as in the flat N=128 case of
W181); fixed build returns `EXR_ERR_CORRUPT_CHUNK`, safe baseline 0.

Inconclusive side probe, preserved as a negative: driving the mixed-channel
PoC of W178 through the same C++ consumer reaches the pinned sink (ASan
`READ of size 128` at `internal_zstd.c:472`), but a filtered gdb readback after
the fortified memcpy wrapper showed no `0x3c`/`0x5a` byte runs at the
destination. The post-`finish` memory read is ambiguous for that wrapper, so
this is not offered as evidence against W178/W181's chosen-byte results; it
only means no C++-path chosen-byte claim is made here.

Replay: three working-tree runs of `sh harness/cpp-heap-victims-check.sh`
gave `RESULT PASS` and hashes
`7cb9f1f8d20246fd63f9fafa4dbb686d0d6179a39b83210ebadcce184b7ac8e4`
(heap observation), `c0d6ac03b8b428e203a31f77a56c431c65463c65bda7333684a944e57d00d03d`
(baseline) and
`5667c65f80bb786ba515e1e0ae845e78182424c922a1ab59b039e6b8aea43eee` (fixed).
Clean-archive replay receipt follows.

Disposition: the no-control-flow-target result now covers both measured
consumers (flat W171 and C++ W182). No wire, no chosen bytes, no pointer or
control-flow write, no command, no marker. No grade change; this section is
unwitnessed and W161 remains the only ESTABLISHED verdict (older all-FLOAT
file). Rung 5 stays UNKNOWN. Would change mind: a measured live code pointer
inside a survivable overwrite, a wire-fed unmodified consumer, or a witness
counterexample.


Clean-archive replay at `59bce1f`: `git archive 59bce1f
lab/openexr2shell-real` into `/tmp/w182-openexr.e3yu9g`, with the gitignored
`bin-vuln-plain`, `bin-fixed-asan` and `cases/baseline.exr` symlinked from the
live tree, reproduced `RESULT PASS` and all three normalized-output hashes
identically to the working-tree runs. Receipt only, no new claim.


## W183: plant-wide wire-consumer inventory — negative (2026-11-24)

Question: since W162 dispositioned the host PATH, has any lab in this plant
gained an unmodified process that accepts EXR bytes over loopback and reaches
the pinned ZSTD sink? Answer: no. This is a read-only inventory from
11:06-11:10Z — no new consumer, build or network probe was created by it.

- Every lab caller of `exr_decoding_run()` on the pinned 3.5.2 library takes a
  local file path: `lab/openexr2shell-real/harness/build.sh:16` links
  `libOpenEXRCore-3_5*.a` from `build-vuln-*`; `harness/flat_harness.c:26,60`
  and `oiiolab/oiio_flat_consumer.cpp:10-14` read `argv[1]`. The unmodified
  `exrcheck -c` needs a readable path (`src/bin/exrcheck/main.cpp:156-166`,
  W162).
- `oiiolab` is configured against the pinned 3.5.2 install
  (`CMakeCache.txt:576,579`; `configure4.log:33,305,310`;
  `exr-install/lib/cmake/OpenEXR/OpenEXRConfigVersion.cmake:12`), but has
  never linked: `build-oiio-target.log` ends in GCC-13's false-positive
  `-Werror=maybe-uninitialized` from `std::regex` in `filesystem.cpp`, and no
  `bin/oiiotool` or `libOpenImageIO_d.so` exists. No linked-OIIO replay has
  occurred, so the advisory's flat-path claim stays a static negative (W173),
  not a dynamic observation.
- The plant's other loopback HTTP harnesses decode other formats:
  `lab/frontier/libvips2shell/real/wire.c:43-56,88` binds 127.0.0.1 and feeds
  the POST body to `vips_image_new_from_buffer()`, but its build
  (`real/build.sh:18-21`) keeps TIFF as the only enabled loader; the
  `imgproxy2shell` probes (`http_probe.py:18-27`, `ico_probe.py:27-30`) serve
  TIFF/ICO fixtures. Neither links OpenEXR.

Disposition: rung 5 still lacks a live affected application process fed by
wire/request input; a purpose-built socket wrapper would be a synthetic
consumer under `docs/rce.md:12-15` and remain rung-4 mechanics. No pointer or
control-flow corruption, command, marker or new grade. Would change mind: an
unmodified network-facing consumer with a deep ZSTD decode path, or a
completed OIIO build reaching `internal_zstd.c:472`.


Bounded build retry, same wake: `timeout 900 nice -n 10 ninja -C
build-oiio-asan -j2` produced only `ninja: Entering directory ...` — not one
of the 123 remaining edges completed in 900s, and no `bin/oiiotool` or
`libOpenImageIO_d.so` appeared. Two `cc1plus` children were left in D state
by the timeout and were killed. A subsequent `ninja -n` also exceeded 300s
under host load ~11-14, so the tree stays UNBUILT and the OIIO replay is not
claimed. The first four-check consolidated replay launched at 11:11Z was cut
by its 1200s deadline with the first ASan `exrcheck` still producing no
output; no result is claimed from that attempt. After the stale compilers
were killed the same four checks completed in seconds — see the receipt
below. Neither failure contradicts any earlier observation: they were
host-capacity limits, not lab counterexamples.



W183 consolidated replay receipt (11:33-11:34Z): after the stuck build's two
D-state `cc1plus` children were killed, all four committed checks completed
in the working tree (`RESULT PASS`, rc 0 each) and again from `git archive
4a6aa17 lab/openexr2shell-real` into `/tmp/w183-openexr-clean` with the
gitignored `src/`, `build-{vuln-asan,vuln-plain,fixed-asan}`,
`bin-{vuln-plain,fixed-asan}`, `cases/*.exr` and `work-*` paths symlinked from
the live tree. Whole-output sha256 values, working tree == clean archive for
all four: `exrcheck-mixed` `ec494e149caa15a9ef05a681b2cdf4aa30fd798c72d8098af04c719972acef31`,
`offset-steer` `3b472bf764c5bc1f7f2454b06c4be45a36cc0fc0f4828ae60157d13290666387`,
`exrcheck-steer` `555085f1f6491cbc01ee14c1eb231507f0abfd44d68585288ff36925876273fa`
(identical to W181's earlier aggregate), `cpp-heap-victims`
`6ecacec424080a0c1ff58ca570f105bd354282cf88ef6a2b1923aad31e0bb644`.
Raw outputs: `lab/openexr2shell-real/evidence/w183-*.out` (committed in
`1d2d6a9`) and `/tmp/w183-clean-*.out` (outside the repo). This is a replay of
author claims, not a witness verdict; grade and rung-5 status unchanged. The
earlier 1200s consolidated-replay timeout was host contention from the same
build, now resolved by killing those stale compilers.



## W184: whole second-stage overwrite is file-chosen (2026-11-24)

Prediction: W178/W181 showed a handful of file-chosen bytes past the destination,
but the first copy still crossed the allocation boundary and its OOB portion
was allocator residue. If the forged `unpacked_size` is large enough to hold the
FLOAT row, the first inverse-sort copy should stay in bounds and the entire
second copy should land past the allocation with every OOB byte coming from the
crafted file.

Method: `cases/make_poc_mixed_full.py` forges a deep ZSTD chunk with `N=64`
samples on the last pixel, `split=2N=128`, grid total `6N=384`, and
`unpacked_size=U=4N=256`. The inner frame carries the two segments that
`exr_zstd_segment_layout()` requires (`128` bytes of 2-byte elements and `128`
bytes of 4-byte elements), both filled with one chosen byte. The baseline EXR
is regenerated with the committed pinned generator. Both variants (0x3c and
0x5a) and the baseline run through `bin-vuln-plain/guarded_harness`, the
fixed 3.5.3 `bin-fixed-asan/guarded_harness`, the unguarded
`bin-vuln-asan/flat_harness`, and gdb breakpoints at the sink and at the
post-decode guard report. The one-command replay is
`sh harness/mixed-full-check.sh`; the PoC hashes are
`1fafb97255ad2178d8d68a1dec703f89b08aba2ac5f647658f3cd9187e6c8ba0`
(0x3c) and `2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7`
(0x5a), both small local files; baseline
`9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04`.

Result: the sink trace (`evidence/full-oob-gdb-copies.out`) shows
`SINKCOPY dst_off=0 src_off=128 n=256` followed by
`SINKCOPY dst_off=256 src_off=0 n=128`. The first copy ends exactly at the
256-byte allocation; the second starts exactly past it. The guarded allocator
reports `GUARD-CHANGE alloc=24 size=256 changed=128 first=+0` with
`actual@first=0x3c` / `0x5a`, and the baseline reports `changed=0`. gdb dumps
all 128 bytes at `decode.unpacked_buffer+256` as the chosen byte for each
variant (`evidence/full-oob-gdb-3c.out`, `-5a.out`). The fixed build rejects
with `DECODE rv=23 EXR_ERR_CORRUPT_CHUNK` and no guard change.

Caveat preserved: the unguarded ASan build aborts earlier, on the first copy's
OOB *source* `READ of size 256` at pinned `internal_zstd.c:472`, so it never
reaches the second copy's write. The guarded allocator backfills each
suballocation with a 16 KiB guard inside one large `malloc` region, which is
why ASan cannot see the suballocation overflow; the WRITE is measured by the
guard bytes and gdb readback, not by ASan. The vulnerable plain build returns
`DECODE rv=31 EXR_ERR_INVALID_SAMPLE_DATA` after the sink, before any further
consumer of the chosen OOB bytes.

Replay: `RESULT PASS` in three consecutive working-tree runs; nine normalized
evidence hashes byte-stable (`evidence/full-oob-*.out`), aggregate normalized
sha256 `d04f151a539362d22d58ec4c4e8c06c4ee0689fd88aa29c5824ba2e7becf946f`.
This is an author replay of a new author claim, not a witness verdict. Scope:
local crafted EXR file, in-process C harness, no wire/socket, pointer or
control-flow target, command or marker. No grade change: file-level rungs 1-4
at the labeled CODE/CONSUMER scope, W161 witness-ESTABLISHED still covers only
the all-FLOAT file, W164/W169/W178/W179/W180/W181/W182 and this W184 remain
unverdicted, and rung 5 stays UNKNOWN. Would change mind: a measured live
control-flow target inside this fully chosen OOB region, or a witness
counterexample.


W184 clean-archive receipt (12:50Z): `git archive aad2c431 lab/openexr2shell-real`
into `/tmp/w184-clean` with the gitignored `src/`, `build-{vuln-asan,vuln-plain,fixed-asan}`
and `bin-{vuln-plain,vuln-asan,fixed-asan}` trees symlinked from the live checkout;
`sh harness/mixed-full-check.sh` there printed `RESULT PASS`, rc 0. All nine
normalized evidence hashes matched the working tree byte-for-byte and the
aggregate sha256 was `d04f151a539362d22d58ec4c4e8c06c4ee0689fd88aa29c5824ba2e7becf946f`
in both. Commit `aad2c431` carries the generator, check script, nine evidence
files and both report sections; this receipt is a separate scoped commit.
Author replay only, not a witness verdict; grade unchanged.


## W185: the fully-chosen 128-byte window contains no steerable pointer (2026-11-24)

Hypothesis tested: W171 reported live `decode.scratch_buffer_1/2` pointer
*values* numerically inside the 4096-byte overwrite; W184's mixed-full file
writes 128 fully file-chosen bytes at `dst+256..+384` and survives in the flat
path. Could those bytes replace a live pointer *field* and steer a later
dereference?

Result: **negative, two measured reasons**.

1. In `bin-vuln-plain/flat_harness` the `exr_decode_pipeline_t decode` is a
   stack local (`harness/flat_harness.c:14`). At the 128-byte COPY2 breakpoint
   the field addresses are on the stack, not in `[dst,dst+128)`:
   `FIELD scratch_buffer_1 stack=1 in_copy_window=0` and the same for
   `scratch_buffer_2`. Their values before and after the copy are unchanged
   (`AFTER ... unchanged=1` for both). W171's `LIVE-PTR-INSIDE` lines are
   pointer values that happen to lie in the heap range, not fields stored
   there. This also explains W177's non-effect at the shorter copy.
2. In the unmodified `build-vuln-plain/bin/exrcheck -c` on the same
   mixed-full PoC, COPY2 still writes `dst_off=256 n=128`, but the window has
   `PTR-HITS total=0` against executable and rodata mappings (W182's scan).
   Three heap-valued qwords at `+16/+24/+32` are values, not demonstrated
   live fields. The process prints `file ... bad` and exits rc 1 with no
   chosen-address fault; the fixed 3.5.3 build rejects the chunk before the
   sink (`DECODE rv=23 EXR_ERR_CORRUPT_CHUNK`, guard unchanged), and a clean
   baseline prints `OK`.

Inputs are W184's pinned baseline (sha256 `9aa2073d...`) and PoC
`work-mixed/poc_mixed_full_3c.exr` (sha256
`1fafb97255ad2178d8d68a1dec703f89b08aba2ac5f647658f3cd9187e6c8ba0`).
One-command replay: `cd lab/openexr2shell-real && sh
harness/heap-window-check.sh` -> `RESULT PASS` 3x in the working tree, with
six byte-stable evidence hashes: pointer fields
`8951bd423a79e775df894ccb3a62153e2200fd1cb8e03557c9a7964da36dc6b5`, heap
window `2e618a108217ed3b84f66372e7ba16d6bb45db4b72bb1dfe3cb0879966ea3fda`,
baseline `9b27412362727eab7e32e8a92f13744f7230e3148c60ae3f75e945adf269a855`,
plain PoC and plain fixed both `e4b0426763a7a024064804c9af1f85e124949f4721725d8f6a6fd2b95b0d7ad8`
(both print `bad`, which is why the separate fixed guarded-harness control
`6d6965fb57b39b4d803d2fbd5bc89dc3828b46474810a0e0d19d5d1dbe5dd98a` records
the earlier `rv=23` rejection).

Disposition: no grade change. File-level rungs 1-4 at the labeled CODE/
CONSUMER scope, W161 witness-ESTABLISHED only for W158/W161, W164/W169/W178/
W179/W180/W181/W182/W184 plus this W185 unverdicted, rung 5 UNKNOWN. No wire,
pointer or control-flow target, command or marker. Would change mind: a live
control-flow target inside a survivable chosen-byte window, a network-facing
unmodified consumer, or a witness counterexample.


W185 clean-archive receipt (13:35Z): `git archive 22a8eeec lab/openexr2shell-real`
into `/tmp/w185-openexr-clean` with gitignored `src/`, `build-*` and `bin-*`
trees symlinked from the live checkout; `sh harness/heap-window-check.sh`
printed `RESULT PASS`, rc 0. All six normalized evidence hashes matched the
working tree byte-for-byte and the aggregate sha256 of the hash listing was
`56e3a182397fac2e76038d5cd1e6a3bc29f44afd4c10b19d5576d0a26a6c3dcf` in both.
Commit `22a8eeec` carries the two probe scripts, the check, the six evidence
files and both report sections; this receipt is a separate scoped commit.
Author replay only, not a witness verdict; grade unchanged.



## W186: live malloc-metadata reach, no steerable behavior (2026-11-24)

Hypothesis: W184 showed 128 fully file-chosen bytes land past the destination
allocation and the process survives with `EXR_ERR_INVALID_SAMPLE_DATA`; W185
showed no live control-flow pointer in that window. glibc chunk headers do
live immediately after a malloc user buffer, so this wake measured whether
the overwrite reaches allocator metadata that the process later consults,
and whether a chosen word in that header steers the outcome.

Method: `cases/make_size_word_poc.py` extends W184's generator so the eight
bytes of segment 1 that become COPY2 source offsets 8..15 encode a chosen
64-bit word. The pinned ZSTD segment transform interleaves segment 1's two
halves (`source[2i] = seg1[i]`, `source[2i+1] = seg1[64+i]`), measured with a
marker-file gdb dump; the wrapper writes `seg1[4:8]` and `seg1[68:72]`. In
unmodified `build-vuln-plain/bin/exrcheck -c`, a hardware watchpoint at
`outPtr+264` stops on the COPY2 write into the adjacent live chunk header.

Measured (`evidence/w186-gdb-chunk.out`):

```
ENTRY own_size=0x111 next_prev=0x40000000010000 next_size=0x31
WATCH next_prev=0x5a5a5a5a5a5a5a5a next_size=0x41 src8=5a5a5a5a5a5a5a5a4100000000000000
```

The live chunk's size word at `dst+264` changes from `0x31` to the fully
file-chosen `0x41`; its `prev_size` at `dst+256` becomes eight chosen bytes.
This is allocator metadata, not a pointer field, and it is reached in an
unmodified consumer.

NEGATIVE on steering: byte-identical PoC `work-mixed/w186a.exr` aborts with
`munmap_chunk(): invalid pointer` (rc 134), while the same bytes copied to
`work-mixed/w186longname.exr` print `bad` (rc 1). The difference is process
heap layout (argv/filename length), not a chosen value. Under nine
equal-length filenames, eight chosen size words (`0x0021` through `0x1011`)
and the uniform-`0x5a` control all produce the same rc 1 / `bad` outcome
(`evidence/w186-size-sweep.out`). No tested word gives a controlled write,
tcache retarget, pointer/IP value or command. Fixed 3.5.3 rejects the chunk
before the sink (`DECODE rv=23`, guard unchanged); baseline decodes `OK`.

One-command replay: `cd lab/openexr2shell-real && sh
harness/chunk-header-check.sh` -> `RESULT PASS` three times in the working
tree; nine byte-stable evidence hashes, aggregate
`f878197c66c812f3fd9ae4d30c9c702441999be8ef3705f25d4f8ce1d1755e01`.
The W184 replay still passes unchanged. Scope: local crafted EXR, in-process
decode in an unmodified tool, no wire, no pointer or control-flow target,
no command, no marker. No grade change: file-level rungs 1-4, witness
ESTABLISHED only W158/W161, W164/W169/W178/W179/W180/W181/W182/W184/W185
and this W186 unverdicted, rung 5 UNKNOWN. Would change my mind: a chosen
word that changes a live pointer or allocation address under a fixed layout,
a wire-fed unmodified consumer, or a witness counterexample.


W186 clean-archive receipt (14:30Z): `git archive 5ebbfdf8 lab/openexr2shell-real`
into `/tmp/w186-clean` with the gitignored `src/` and `build-*`/`bin-*`
trees symlinked from the live checkout; `sh harness/chunk-header-check.sh`
printed `RESULT PASS`, rc 0. All nine normalized evidence hashes matched the
working tree byte-for-byte and the aggregate sha256 of the hash listing was
`f878197c66c812f3fd9ae4d30c9c702441999be8ef3705f25d4f8ce1d1755e01` in both.
Three further working-tree replays were byte-identical. Commit `5ebbfdf8`
carries the generator extension, the wrapper, the gdb probe, the check, the
nine evidence files and both report sections; this receipt is a separate
scoped commit. Author replay only, not a witness verdict; grade unchanged.


## W187: file-chosen tcache next steers a live malloc address (2026-11-24)

Hypothesis: W186 measured the W184 fully-chosen 128-byte COPY2 window reaching
a live malloc chunk header at `dst+256/264`; its named open question was
whether a chosen word could change a live allocation address under a fixed
layout. The untested step is the chunk's *user* data at `dst+272`. If that
chunk is a freed glibc tcache entry, its first eight user bytes are the
safe-linked `next` pointer and the fully chosen window can redirect a later
allocation.

Method: `harness/tcache_harness.c`, compiled `-no-pie` against the pinned
plain 3.5.2 library, primes A (0x110, the destination), B (1000 bytes, 0x3f0)
immediately after A, C (0x110, consumed first as the 256-byte sample-count
table), a trailing 0x3f0 entry X, and five more 0x3f0 entries D0..D4; the
frees leave `tcache[0x110] = [C,A]` and `tcache[0x3f0] = [D4..D0,B,X]`.
`exr_decoding_run()` takes C then A, so COPY2's 128 file-chosen bytes at
`A+256..+384` cover B's header and its user bytes 0..111. The eight bytes at
source offsets 16..23 land at `A+272`, i.e. `B->next`;
`cases/make_tcache_poc.py` encodes `(B >> 12) ^ target` there, exactly
glibc 2.39's safe-link inverse. Seven `malloc(1000)` calls then walk
D4..D0, B, and the pointer stored in B.

Observed with ASLR off (`setarch -R`):

- Crafted file for target `0x4e6b40` (a benign `-no-pie` global in the
  harness): vulnerable 3.5.2 prints `DECODE rv=31`,
  `TCACHE stored_next=0x00000000004e6ecc`, `M6=0x58c480` (B), and
  `M7=0x4e6b40` exactly. A second file targeting `anchor+0x10` gives
  `M7=0x4e6b50`. Two distinct file-chosen targets, two distinct returned
  live allocation addresses.
- Uniform `0x5a` control: `stored_next=0x5a5a5a5a5a5a5a5a`, `M6=B`, then
  `malloc(): unaligned tcache chunk detected` and rc 134 — glibc follows the
  chosen pointer and rejects it for alignment.
- Valid baseline on the same vulnerable harness: `DECODE rv=0`, B's next is
  its ordinary safe-linked link to X, and `M7=X`, not the target.
- Fixed 3.5.3 on the same crafted file: `DECODE rv=23 EXR_ERR_CORRUPT_CHUNK`,
  B's next stays its link to X, `M7=X`; the fixed guarded harness reports
  `GUARD-TOTAL post-decode changed=0`.

One-command replay: `cd lab/openexr2shell-real && sh
harness/tcache-steer-check.sh` -> `RESULT PASS`, eight normalized evidence
hashes byte-stable in three consecutive working-tree runs (sha256 of the full
check output `6f668b1dba31a12e3aa9cfa6a89da49e0105fe7835b767306c344eadef8db4e6`;
sha256 of the hash listing alone
`88c63c555cc91bf68f2412b8b01512682cd75c308139be1f02a52349635d78aa`).
Relations are recorded outside address normalization in
`evidence/tcache-relations.out`: `targeta ... steer=1`, `targetb ... steer=1`,
`baseline ... steer=0 fell_through_to_X=1`, `fixed ... steer=0
fell_through_to_X=1`.

Scope and ceiling: local crafted EXR, purpose-built C harness, harness-supplied
tcache grooming, ASLR off and a fixed `-no-pie` target. File-chosen bytes steer
a live heap allocation address under that measured layout — a rung-4 pointer/
control-datum result, not control flow. No wire, no code pointer or IP, no
command, no marker side effect and no witness verdict. W161 remains the only
ESTABLISHED verdict (W158 direct-call and W161 all-FLOAT file); file-level
rungs 1-4 stay the grade and rung 5 stays UNKNOWN. Would change my mind: the
same address steering in an unmodified consumer, a chosen code pointer or IP,
a wire-fed affected process, or a witness counterexample.


W187 clean-archive receipt (18:06Z): `git archive 45928e64 lab/openexr2shell-real`
into `/tmp/w187-clean`, with the gitignored `src/`, `build-{vuln-plain,vuln-asan,
fixed-plain,fixed-asan}` and `bin-*` trees symlinked from the live checkout;
`sh harness/tcache-steer-check.sh` printed `RESULT PASS`, rc 0. All eight
normalized evidence hashes and the four relation lines matched the working
tree byte-for-byte, with the same check-output digest
`6f668b1dba31a12e3aa9cfa6a89da49e0105fe7835b767306c344eadef8db4e6`.
Commit `45928e64` carries the harness, generator, check, twelve evidence files
and both report sections; this receipt is a separate scoped commit. Author
replay only, not a witness verdict; grade and rung-5 status unchanged.


## W188: no tcache next pointer in the unmodified consumer's overwrite window (2026-11-24)

Prediction and decision: W187 proved file-chosen allocation-address steering
only after the harness explicitly freed a 0x3f0 chunk immediately after the
256-byte `uncompressed_buffer`. If that grooming is an artifact of the
harness rather than of the file, UNMODIFIED `exrcheck -c` should have no
tcache `next` word inside the same copy window at the moment of the sink.
That prediction held; the W187 condition is harness-supplied, and the file
alone does not recreate it here.

Probe: `harness/tcache-reach.cmd` breaks at
`sort2_4ByteChannels_tiled` entry, reads glibc 2.39 `tcache` (`counts[64]`
uint16 at offset 0, `entries[64]` pointers at offset 128), follows each chain
with `PROTECT_PTR` demangling `(chunk >> 12) ^ stored`, and prints
`(chain index, offset from outPtr)` for every tcache user pointer in
`dst+0..dst+384`. Absolute addresses are normalized away; offsets remain so
the distance to the window is auditable.

Inputs are the same three equal-length-path files used by W184/W186:
`work-mixed/w188-c0.exr` (valid baseline, sha256
`9aa2073dce40b893f648f0fb078b738538e65a569cb00079d4128612e7fa3d04`),
`w188-c1.exr` (fully file-chosen COPY2, sha256
`2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7`) and
`w188-c2.exr` (W186 size-word PoC, sha256
`76db069d0677e5f9bfb87336a9c3a69a54e1dac2499248129339cc705da73e1e`).
All are regenerated by the check from committed generators.

Observed at the sink, under `set disable-randomization on`:

- Detector sensitivity, groomed `-no-pie` harness with `w188-c1.exr`:
  `TCACHE idx=7 size=0x90 n=1 head_off=+3104 hits=[]` and
  `TCACHE idx=61 size=0x3f0 n=7 head_off=+7744 hits=[(5, 272)]`. The
  harness-supplied chunk sits exactly where W187's chosen bytes reach.
- UNMODIFIED vulnerable `build-vuln-plain/bin/exrcheck -c`:
  only `TCACHE idx=7 size=0x90 n=1 head_off=+4448 hits=[]` on the baseline
  and `head_off=+4288 hits=[]` on both crafted files. The nearest tcache
  user pointer is 4288 bytes past the destination, 3904 bytes beyond the
  end of the 384-byte copy window. No tcache `next` word is overwritten.
- W186's live adjacent chunk is still reached (`next_size` changes from
  0x31 to the file-chosen word); it is live, not a tcache entry, at the sink.

One-command replay: `cd lab/openexr2shell-real && sh
harness/tcache-reach-check.sh` -> `RESULT PASS`, rc 0, three consecutive
byte-stable working-tree runs; full check-output sha256
`696dc8cbf18954296269dd205305707499d93b09a78d7b4dc21bb57300d2d3c0`,
evidence hashes `c0 7eef864673b647c360b802a0f6167b1cd2d61ffeba22ffe74eae1092a13d8aa5`,
`c1 = c2 1cf7f25c088f9ce4054c314f0aa6882a7eb9d51089a0c507b6e4e260915129a9`,
`harness 93a751b2471e7139e7e944386b83feab2a987c2c33cf438d4f06be0c20fa6d1b`.
The check also fails if any consumer probe reports a window hit, so a future
layout or build change that closes this gap is detected rather than silently
folded into a pass.

Ceiling: a gdb observation on one pinned build, three files, equal-length
paths and ASLR off. It bounds the W187 steering condition to a groomed
harness under this layout; it does not prove the absence of every possible
consumer layout, and it is not a witness verdict. No wire, code pointer, IP,
command, marker or process-level side effect. Grade stays file-level rungs
1-4 with a separate harness rung-4 allocation-address datum; rung 5 remains
UNKNOWN. Would change my mind: a tcache entry inside the window in an
unmodified consumer, a chosen code pointer/IP, a wire-fed affected process,
or a witness counterexample.

W188 clean-archive receipt (18:31Z): `git archive 5057e7ed lab/openexr2shell-real`
into `/tmp/w188-clean`, with the gitignored `src/`, `build-{vuln-plain,
vuln-asan,fixed-plain,fixed-asan}` and `bin-*` trees symlinked from the live
checkout; `sh harness/tcache-reach-check.sh` printed `RESULT PASS`, rc 0, and
the same full check-output sha256
`696dc8cbf18954296269dd205305707499d93b09a78d7b4dc21bb57300d2d3c0` with all
four normalized evidence hashes byte-identical to the working tree. Commit
`5057e7ed` carries the gdb probe, generator-backed check, four evidence files
and both report sections; this receipt is a separate scoped commit. Author
replay only, not a witness verdict; grade and rung-5 status unchanged.


## W189: heap-layout knobs do not put tcache pointers in the W184 window (2026-11-24)

Prediction and decision: W188 found one live 0x90 tcache head 4288 bytes past
the destination in UNMODIFIED `exrcheck -c`. Two external layout knobs could
plausibly move it into `dst+0..dst+384`: argv path length (the Core context
copies the filename into a heap string, `context.c:169`
`exr_attr_string_create`) and earlier valid files decoded in the same process
(each decode allocates and frees chunks before the crafted one). Either could
give W187's file-chosen COPY2 bytes a real tcache `next` to steer. Both
predictions failed: no probe ever reported a window hit.

Method: the same pinned W184 PoC (`cases/make_poc_mixed_full.py` with N=64,
fill 0x5a, U=256, sha256
`2ab3ea9751736720030d606cd3dd947dd000039da537a47bf822f1f18dd618f7`) was fed
to `build-vuln-plain/bin/exrcheck -c` under `set disable-randomization on`.
`harness/tcache-reach.cmd` enumerates glibc 2.39 tcache chains at the sink;
`harness/tcache-reach2.cmd` is the same probe without `delete 1`, so a
conditional breakpoint can select a later decode. Both normalize absolute
addresses and keep offsets relative to `outPtr`.

Path-length sweep: `harness/layout-sweep.py` creates symlinked paths of exact
length 24, 32, 64, 96, 128, 160, 200, 248, 300, 512, 1024, 2048, 3072 and
3900 bytes, all resolving to the identical PoC bytes. Every probe printed
exactly `TCACHE idx=7 size=0x90 n=1 head_off=+4288 hits=[]`, byte-for-byte the
W188 short-path control. Path length changed no tcache head offset at all in
this build.

Prior-decode sweep: N=0..8 valid deep-ZSTD baseline files were passed before
the PoC in one `exrcheck -c` invocation; the breakpoint condition
`inPtr[0] == 0x5a` selects the PoC's sink. N=0 reproduced W188
(`head_off=+4288 hits=[]`). For N>=1 the chain layout is deterministic by
parity: odd N gives `idx=1 +3488`, `idx=7 +3248`, `idx=23 n=3 +832`; even N
gives `idx=1 -448`, `idx=7 +3248`, `idx=23 n=3 -928` (with stable `idx=2
-1264` and `idx=6 -1392`). `hits=[]` in every one of the nine probes; the
nearest live tcache pointer is +832, 448 bytes beyond the 384-byte
file-chosen window. The full chain walk, not just the head, was checked.

One-command replays: `cd lab/openexr2shell-real && sh
harness/tcache-layout-sweep.sh` -> `RESULT PASS (no tcache next pointer in
copy window, 14 path lengths)`, rc 0; `sh harness/tcache-prior-sweep.sh` ->
`RESULT PASS (no tcache next pointer in copy window, 0..8 prior files)`, rc 0.
Each runs two byte-stable passes with sha256 comparison; full check-output
sha256 `3cd9b99f9ac5a5471d03c189a46dcd7d3db74a8d514f578e026612ef5ecd6ea8`
(layout) and
`659a6cba9d1842f0fb798ddbf685c6cba4a58ff566fb371ca0d3437bd1d9d774` (prior),
aggregate evidence sha256
`a743fea9b0b731c57c0a83dd00009c5dae9e9dd05aecc31f1f412e96b47ff418` over 26
normalized probe files and two summaries. Both checks fail on any future
window hit.

Ceiling and disposition: one pinned build, one PoC fill byte, ASLR off, gdb
observation only. Path length and prior-file count are lab knobs, not
file-supplied bytes or wire input; other keep/recycle layouts, builds and
consumers remain UNKNOWN. Keep W188's negative and extend its boundary to
these two knobs. No code pointer or IP, no command, marker, socket or wire,
no witness verdict, no rung-5 claim. Would change my mind: a nonempty `hits`
in an unmodified consumer, a chosen code pointer/IP, a wire-fed affected
process, or a witness counterexample.

W189 clean-archive receipt (19:39Z): `git archive 8b44da3d lab/openexr2shell-real`
into `/tmp/w189-clean`, with the gitignored `src/`, `build-*` and `bin-*`
trees symlinked from the live checkout. Both replays printed `RESULT PASS`,
rc 0, with check-output sha256
`3cd9b99f9ac5a5471d03c189a46dcd7d3db74a8d514f578e026612ef5ecd6ea8` and
`659a6cba9d1842f0fb798ddbf685c6cba4a58ff566fb371ca0d3437bd1d9d774` and
aggregate evidence
`a743fea9b0b731c57c0a83dd00009c5dae9e9dd05aecc31f1f412e96b47ff418`,
byte-identical to the working tree. Commit `8b44da3d` carries the two probes,
both replay scripts, the path generator, 26 evidence files and both report
sections; this receipt is a separate scoped commit. Author replay only, not
a witness verdict; grade and rung-5 status unchanged.

## W190: file-chosen bytes reach a live tcache `next` in unmodified exrcheck (2026-11-24)

W188/W189 measured no tcache user pointer inside the 384-byte chosen-byte
window at their fixed geometry and concluded that the file alone supplied no
tcache grooming *there*. W180/W181 showed the forged sample count N scales
the second inverse-sort copy's destination offset to 4N. The bounded question
was whether a larger file-forged N moves that copy onto the live 0x90 tcache
head W188 saw at `dst+4288`. Prediction: no — the layout or the process would
break first. The prediction failed: the file alone places file-chosen bytes
in a live tcache `next` word in the UNMODIFIED upstream `exrcheck -c` binary.

Method: `cases/make_poc_mixed.py` with N=1072 and fill 0x5a/0x3c/0x00 (sha256
`663d02672f973b5d0affd36364185729551157be1928f5c48ad3e7d365b45c16`,
`3f969d0524e681840035a5642aa92a3f8ef7de7c1d6affc7fce1356e62d4034d`,
`1c57f2570a366d765d38777dbc49ecbd1c59e5a11ce0e6c4e43890aeddec46f2`).
The forged chunk declares `unpacked_size=2N=2144`, sample grid total `6N`,
`split=2N`. Under `set disable-randomization on`, `build-vuln-plain/bin/exrcheck
-c` reaches `sort2_4ByteChannels_tiled`; `harness/w190-tcache-overflow.cmd`
enumerates tcache heads at sink entry, then reads the watched word at the
first and second `__memcpy_avx_unaligned_erms` call.

Observed at the sink (normalized `evidence/w190-gdb-n1072-5a.out`):
`WINDOW_HEADS=[(7, 4304)]`, `TCACHE-WATCH idx=7 off=+4304`, `COPY1
dst-out=+0 len=4288`, `COPY2 dst-out=+4288 len=2144`,
`NEXT-BEFORE-VAL=0x0000000555555828` (glibc safe-linked pointer),
`NEXT-AFTER-VAL=0x5a5a5a5a5a5a5a5a`. The 0x3c and 0x00 files give
`0x3c3c3c3c3c3c3c3c` and `0x0000000000000000` at the same word: the bytes
track the file fill, not debugger residue. All three probes then report
`double free or corruption (!prev)` / SIGABRT. No allocation from the poisoned
tcache is claimed; the abort's causal attribution to COPY1's adjacent-header
damage versus the poisoned `next` is UNKNOWN.

One-command replay: `cd lab/openexr2shell-real && sh
harness/w190-tcache-check.sh` prints `RESULT PASS` rc 0. It pins the generator
and three PoC hashes, asserts the live head offset, both copy lengths/offsets,
three distinct next-word values, a rc-0 valid-file control, an ASan control
(`READ of size 4288`, `internal_zstd.c:472`, `exr_decoding_run` via
`build-vuln-asan/bin/exrcheck`, rc 1) and the fixed 3.5.3 control (`bad`, rc 1,
no ASan). Three in-tree runs are byte-identical, check-output sha256
`ba155b40d9fb04aea70cb7a00eda7fe72b1a593eaded0dcd2be1cae42de087ea`; core
evidence hashes: baseline `fb460d748a257b2975615fb56ea211f6faa075621cab9d0bbcaadcda086c2dba`,
gdb 0x5a `0fc5606b3db9703728ceae54c3f63522f9d88cb0a00530bd91b63735ae97e29f`,
0x3c `91023a9db8f8a5ababc0fd8d782bd65407c6492c62a1187f998783c4e73793a3`,
0x00 `aef25de79a27a39d370cb34917e901f72ff88b92142cdd951c46660a603c1c93`,
ASan `d05a7c5591e761ac7d65bb6aa13c35673c85a49effa745b356f1f178fd752e2d`,
fixed `e63912b5f9fcaa53f61c023cc4366cbac5ebeb020ef2924cfe24490e1e00e76c`.

Ceiling and disposition: one pinned 3.5.2 build, one forged geometry, equal-
length paths, ASLR off, gdb observation; N and fill are file bytes but the
genesis of the 0x90 tcache head is a layout fact of this consumer, not a
file-steered allocation. This is rung 4 — file-chosen bytes at a known offset
over a live heap metadata word in an unmodified consumer — not steering, no
code pointer/IP, no control-flow diversion, no command, marker, socket or
wire, no witness verdict; rung 5 remains UNKNOWN. W188/W189 stand for their
own geometries. Would change my mind: an observed malloc from the poisoned
tcache, a chosen code pointer/IP, a wire-fed affected process, or a witness
counterexample.

W190 clean-archive receipt (21:54Z): `git archive ecf3f821 lab/openexr2shell-real`
into `/tmp/w190-clean`, with the gitignored `src/`, `build-vuln-plain`,
`build-vuln-asan`, `build-fixed-asan`, `bin-vuln-plain` and `bin-fixed-asan`
trees symlinked from the live checkout. `sh harness/w190-tcache-check.sh`
printed `RESULT PASS`, rc 0; the six core evidence hashes and check sha256
`ba155b40d9fb04aea70cb7a00eda7fe72b1a593eaded0dcd2be1cae42de087ea`
matched the working tree byte-for-byte. Author replay, not a witness verdict;
grade and rung-5 status unchanged.

W190 follow-up negative (21:58Z): `harness/w190-tcache-use.cmd` sets a
hardware watchpoint on `tcache->entries[7]` immediately after COPY2 poisons
the 0x90 chunk's `next`. In `evidence/w190-tcache-use.out` (sha256
`91efa8d884995b023080d70c10cb6b459bf45adc0cf31ca960fe8618e18a4836`) the
watchpoint is installed once and never fires: the next stop is
`double free or corruption (!prev)` / SIGABRT. No allocation consumes the
poisoned tcache in this consumer before the abort, so W190 remains chosen
bytes in live metadata, not demonstrated steering. Grade unchanged; the
watchpoint is a one-off probe, not part of `w190-tcache-check.sh`.
