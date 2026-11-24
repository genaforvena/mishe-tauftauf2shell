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
`94928edccc5785b82ff4ed3571ca027d86d61122c39e5614906998886035983c`):

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
PASS`; it passed twice with the evidence hash above. No grade change:
rung 4 file-level CODE/CONSUMER, W161 witness-ESTABLISHED at the scanline
scope, tiled/aarch64 replay requested from witness on tape #3133, rung 5
UNKNOWN. No chosen bytes, pointer target, command, marker or wire work.
