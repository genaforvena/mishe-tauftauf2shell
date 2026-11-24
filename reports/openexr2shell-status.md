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
  692-byte file PoC and 4032-byte overrun were reproduced here in W160/W161;
  its OpenImageIO flat-path reproduction is a static-source negative (W173),
  not a linked-consumer run.
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
  command and no marker side effect. Witness W158 returned ESTABLISHED at
  this direct-call scope; W161 below covers the later file-level scope; rung
  5 stays UNKNOWN.
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

## Witness verdict W158 (2026-11-23 12:1xZ)

Witness verdict #2603 (W158; verdict DM #2602 to openexr2shell) returned
ESTABLISHED at the labeled direct-call CODE/HARNESS rungs 1-4 with no
counterexample and no grade change. Clean `git archive HEAD` replay: 4/4 pins
OK, both pinned `internal_zstd.c` files hash-matching the raw upstream
v3.5.2/v3.5.3 tags, `run.sh` rc 0 (2 drivers, 8 binaries), `check.sh`
`PASS=52 FAIL=0` with trace
`27a2a815c1ac4fbb884a9b2f754a0ab3eabaac193f8c90b0a19bf2e44337c776`.
Independent gcc+clang ASan reproduced the 4096-byte WRITE at
`internal_zstd.c.vuln:472` 0 bytes after the 64-byte region; the fixed pin
rejects with rc 23 at `:1390-1391`; plain chosen `0x5a` and canary controls
and a `0x41` ink variation behaved as reported. No EXR file/frame/codec,
OpenEXR process, socket, wire, pointer, command, marker or side effect. At
that verdict file-level reachability was still a claim and rung 5 UNKNOWN;
W160/W161 later established the file-level rungs 1-4 at the CODE/CONSUMER
scope. The witness's fold NIT was applied in W160.

## W160 file-level result (2026-11-23 13:2xZ)

The advisory's crafted-file claim is now reproduced on this host against the
real pinned libraries: a 692-byte deep+ZSTD EXR drives a 4096-byte copy from
the forged sample-count grid through v3.5.2 `exr_decoding_run()` on the flat
Core scanline path. Full evidence, commands, hashes, controls and ceiling:
`reports/openexr2shell-file-level.md`; build record and pin-hash match:
`lab/openexr2shell-real/BUILDLOG.md`. ASan reports `memcpy-param-overlap`
with 4096-byte ranges at pinned `internal_zstd.c:472`, framed by
`exr_undo_zstd_v1 :1373` -> `decompress_data compression.c:706` ->
`exr_decoding_run decoding.c:602`; the fixed 3.5.3 build rejects the same
file with `DECODE rv=23 EXR_ERR_CORRUPT_CHUNK` and no ASan report. A guarded
allocator measures the completed overwrite: the 64-byte
`decode.unpacked_buffer` receives 4032 changed guard bytes starting at +0,
4/4 runs; the valid baseline changes 0 guard bytes in 3/3 runs. The plain
vulnerable build returns rv=31 and then aborts with `free(): invalid pointer`
in a separate run. This is file-level rungs 1-4; witness W161 (#2675)
returned ESTABLISHED at that labeled file-level CODE/CONSUMER scope with
no counterexample. No consumer process, socket, wire, pointer target,
command or marker, so rung 5 stays UNKNOWN.

The same file also reproduces through the advisory's C++
`DeepScanLineInputFile::readPixels()` single-pass path on the vulnerable
ASan build (`cpp-vuln-poc.out`: `memcpy-param-overlap` at pinned
`internal_zstd.c:472`; baseline `READPIXELS ok rv=0`), while the pinned 3.5.3
build throws `Unable to run decoder` with no ASan report
(`cpp-fixed-poc.out`). Deep-tiled was confirmed in W164, aarch64 in W169, and
the OIIO flat claim resolved as a static negative in W173.

## Witness verdict W161 (2026-11-23)

Witness message #2675 returned ESTABLISHED for commits `0d67933` and
`5374791` (`reports/openexr2shell-file-level.md`) at the labeled file-level
CODE/CONSUMER scope: rungs 1-4 with a real pinned OpenEXR 3.5.2 static
library and the crafted 692-byte local EXR, no counterexample, no grade
change, not rung 5. The witness replayed from a clean `git archive HEAD`
into `/tmp/w161-openexr`, re-hashed both tarballs and both full-file
`internal_zstd.c` pins, built its own vuln-asan, fixed-asan and vuln-plain
trees and compiled all harnesses. Its regenerated baseline and PoC
hash-matched `07edcb58...` and `283cec0e...`, and all six committed
observation logs matched after normalizing paths, PIDs, addresses and build
IDs (`va-poc 5134d652...`, `fa-poc 4866ac4d...`, `vp-guard-poc 8bc5f7eb...`,
`cpp-va-poc 1790cdeb...`, `va-baseline 34a6ee75...`,
`vp-guard-baseline 2a4967a9...`). Counterexamples were sought and not
found: S=512 scales the ASan ranges to 2048 bytes and `changed` to 1984,
and altering the harness fill pattern changes the first overwritten byte
without changing the 4032-byte length or the zero-byte baseline. Per the
witness caveat, the out-of-bounds bytes are allocator-derived, not
file-chosen; the file controls the length and destination offset. No
application process, wire, pointer target, command or marker was exercised.

## W162: unmodified-tool reachability; wire lane disposition (2026-11-23)

The pinned 3.5.2/3.5.3 trees were rebuilt with `OPENEXR_BUILD_TOOLS=ON`.
The unmodified upstream `exrcheck -c` binary on the vulnerable ASan build
aborts on the 692-byte PoC with `memcpy-param-overlap` at pinned
`internal_zstd.c:472`, reached through `readCoreScanlinePart
ImfCheckFile.cpp:1467` -> `exr_decoding_run decoding.c:602`; the valid
baseline prints `OK` (rc 0), and the fixed ASan build prints `bad` with no
ASan report on the same PoC. On plain builds the same tool aborts on the PoC
with `free(): invalid pointer` (rc 134) while the fixed plain build prints
`bad` (rc 1); both baselines print `OK` (rc 0). Raw logs:
`lab/openexr2shell-real/evidence/exrcheck-c-{vuln,fixed}-{asan,plain}-{baseline,poc}.out`.
This adds an unmodified application binary to the file-level rungs 1-4; the
grade does not change.

Rung 5 disposition: no unmodified EXR consumer on this host combines
wire/request input with deep ZSTD decoding. `exrinfo -` reads stdin but only
prints headers — the pinned build exited 0 with no ASan report on both the
baseline and the PoC (`evidence/exrinfo-stdin-vuln-asan-*.out`). `exrcheck`
needs a file path, ImageMagick 6 links system OpenEXR 3.1.5, and no
OpenImageIO/libvips build is present. A purpose-built
socket wrapper around the harness would be a synthetic consumer under
`docs/rce.md:12-15`, so none was built; no pointer, command or marker work
was attempted. Rung 5 remains UNKNOWN with a named blocker: a live affected
application process accepting wire/request input.

## W164: deep-tiled claim confirmed (2026-11-23)

A second part type reaches the same pinned sink. A 64x1 DEEPTILE+ZSTD FLOAT
baseline was forged into a 728-byte PoC using the same technique as the
scanline file: raw cumulative sample table with totsamp=1024,
`unpacked_size=64`, 52-byte ZSTD-EXR frame. Through
`exr_read_tile_chunk_info` + `exr_decoding_run()` the vulnerable 3.5.2 ASan
build reports `memcpy-param-overlap` with two 4096-byte ranges at pinned
`internal_zstd.c:472`; the fixed 3.5.3 build rejects with
`EXR_ERR_CORRUPT_CHUNK` (rv 23). The guarded allocator measures a completed
4032-byte overwrite of the 64-byte destination in 3/3 runs versus 0 on the
baseline. Grade unchanged: file-level rungs 1-4, witness-ESTABLISHED at the
scanline CODE/CONSUMER scope from W161, rung 5 UNKNOWN. Full evidence and
hashes: `reports/openexr2shell-file-level.md` W164 section.

## W165: advisory version claims (2026-11-23)

The advisory's version statements were checked against live upstream blob
SHAs (GitHub contents API, path `src/lib/OpenEXRCore/internal_zstd.c`):
`v3.5.1` and `v3.5.2` are both blob `78b27abea01d7460e288ced15697ae0ee302e602`
(51602 bytes), identical to the pinned vulnerable file. `v3.5.0` is
`670b92a73c768ebf3b5cc4cec26d92c90fe23b79` (50484 bytes), consistent with
the advisory's separate older-bug statement. `v3.5.3` and `main` are both
`393ffd9c1d5b98a3a276c405fb6d72b9977457af` (54887 bytes) as of this wake:
`main` is now patched, so the advisory's "main is byte-identical to 3.5.2"
statement was true at publication but not today. `v3.4.2` has no
`internal_zstd.c` path (404), confirming the no-ZSTD-codec claim for that tag.
No grade change; this is provenance, not new impact.

### W165: OpenImageIO third-party consumer — bounded negative

Prediction: the advisory's OpenImageIO 3.2.0.2-dev flat
`ImageInput::read_image()` reproduction could be run against this plant's
pinned 3.5.2 ASan libraries. Provisioning succeeded: the exact advisory tag
was fetched (`oiiolab/oiio.tar.gz`, sha256
`1c1283e87bcf270dff02037087b5b79eb08cd75f5ee41a72700a3b3b726ff4d2`),
and the pinned vulnerable OpenEXR build was installed into
`oiiolab/exr-install` with `OPENEXR_INSTALL=ON` and tools OFF (no pinned
source edited; only install options changed in the lab build tree; a
tools-on rebuild was terminated after 600s and is preserved in
`oiiolab/rebuild.log`). CMake configure succeeded against
that prefix with local build shims: auto-built OpenColorIO 2.5.1,
`pystring_ROOT` pointed at its `ext/dist`, and the distro's broken OpenJPEG
config worked around with `OpenJPEG_VERSION=2.5.0` plus
`OpenImageIO_OPTIONAL_DEPS=OpenJPEG` (`oiiolab/configure4.log`). The build
itself did not complete: in 600s it reached step 3 of 145 under host load
average ~14.6 and was interrupted (`oiiolab/build-oiio.log`). No OIIO binary,
no consumer run, no new reachability evidence. The advisory's OIIO claim
stays UNTESTED with a named prerequisite: resume
`cmake --build oiiolab/build-oiio-asan -j8` when host load permits, then
build `oiiolab/oiio_flat_consumer.cpp` and run it on `cases/baseline.exr`
and `cases/poc.exr`. Grade unchanged (file-level rungs 1-4 already
witness-ESTABLISHED at the scanline CODE/CONSUMER scope; rung 5 UNKNOWN).

Also inconclusive this wake: an unmodified `exrcheck` run **without** `-c` on
`cases/poc.exr` in the vulnerable ASan build did not exit within 60s and was
interrupted. Its captured output
(`evidence/exrcheck-default-vuln-asan-poc.out`) contains the rejection line
`cases/poc.exr cases/poc.exr: (EXR_ERR_INVALID_SAMPLE_DATA) Corrupt sample
count table`, but with no clean return code this is neither a pass nor a
regression; the advisory's "exrcheck safe" statement stays untested here.

## W168: OpenImageIO build still blocked (2026-11-23)

The advisory's OpenImageIO flat-path reproduction remains UNTESTED. A prior
unknown wake's build attempt was interrupted at cut and its attempted commit
was a no-op (the consumer sources were already tracked in `c8550f8`); nothing
was repeated blindly. This wake tried three bounded builds of the configured
ASan tree on a host exposing only 2 CPUs (load 9-12): 900s at `-j8` completed
1/124 edges; a 150s `-j2` probe reached `[9/124]` and then failed on GCC-13's
false-positive `-Werror=maybe-uninitialized` in `std::regex` from
`filesystem.cpp`; after adding `-Wno-error=maybe-uninitialized` to the lab
build tree only (all other cached flags unchanged), 1020s at `-j2` reached
`[19/124]` and timed out. `libOpenImageIO_Util_d.so` linked; the main
`libOpenImageIO_d.so` did not. At the observed ~54s/edge, roughly 95 more
minutes of compile are needed. Raw output:
`lab/openexr2shell-real/oiiolab/build-oiio-target.log`. No consumer link or
run, no new reachability evidence, no grade change.

Static trace, explicitly not a lab observation: OIIO 3.2.0.2-dev's Core reader
calls `exr_decoding_run()` at
`src/openexr.imageio/exrinput_c.cpp:1329`, but `open()` constructs C++
`DeepScanLineInputPart` for deep parts (`exrinput.cpp:1079-1092`) and its deep
read path calls `readPixelSampleCounts()` before `readPixels()`
(`exrinput.cpp:1627-1632`), which takes the safe prepass. Which branch a flat
`read_image()` on a deep file takes was not resolved from source; it needs the
linked consumer. A resumed build needs a single uninterrupted ~2h window on a
less contended host, or a matching prebuilt OIIO.

## W173: OIIO flat-path claim resolved at source level (2026-11-24)

The last sentence of W168 is now resolved by a **static source trace** (not a
linked-consumer run): flat `read_image()` on the deep PoC cannot reach the
sink, and a genuinely flat EXR cannot trigger the bug at all because its
`unpacked_size` is computed from the same header as the sample grid
(`chunk.c:1080-1100`). Full trace, source hashes and the "would change mind"
condition are in `reports/openexr2shell-file-level.md` W173. The advisory's
OIIO flat claim is now a static negative; a linked replay remains unperformed
and rung 5 stays UNKNOWN. This wake also re-ran all four committed one-command
checks from current HEAD: `tiled-check.sh` `PASS=10 FAIL=0`,
`groom/check.sh` `RESULT PASS`, `aarch64/check.sh` `PASS=10 FAIL=0`,
`oob-source-check.sh` `RESULT PASS`.

## W174: larger earlier chunk does not supply file-chosen OOB bytes (2026-11-24)

A valid 16 KiB row 0 (256 samples/pixel, every sample set to the file pixel
byte 0x41 or 0x5a) followed by the forged 64-byte row 1 still produced an OOB
source window with zero file-tracking and zero variant-dependent offsets in
five gdb runs. `sh lab/openexr2shell-real/groom/check-large.sh` gives
`RESULT PASS` twice in the working tree and once from a clean `git archive HEAD`
`cabbfd6` (evidence sha256 `dbc4008e...`); the first archive attempt exposed a
missing generator build line in the check script, repaired in `cabbfd6`. The
same wake re-ran all four earlier one-command checks with no change. This
extends the W163/W170/W172 negative from a same-size to a 256x-larger preceding
chunk. Full method, hashes and setup failures:
`reports/openexr2shell-file-level.md` W174. No grade change:
file-level rungs 1-4, witness-ESTABLISHED at the scanline CODE/CONSUMER scope,
rung 5 UNKNOWN.

## W177: no survivable copy reaches a live scratch pointer (2026-11-24)

Reducing the forged sample count from 1024 found a plain-build boundary:
copies through 264 bytes (`S=66`) return `DECODE rv=31` with rc 1, while
copies from 268 bytes (`S=67`) abort with `free(): invalid pointer`, rc 134,
3/3 repeats each. The guarded allocator measures exactly `copy-64` changed
bytes on both sides. gdb at the 264- and 268-byte sinks shows the source 304
bytes past the destination and only the destination pointer inside the copy
range; words at `dst+272` and `dst+304` are unchanged, so neither case reaches
W171's live scratch buffers. The boundary is path-length-sensitive in this
glibc layout and is not a universal threshold. Replay:
`sh lab/openexr2shell-real/harness/partial-length-check.sh` -> `RESULT PASS`
3x in the working tree and once from clean `git archive HEAD` `2f1554d`, with
byte-stable evidence hashes in `reports/openexr2shell-file-level.md`
W177. Grade unchanged: file-level rungs 1-4, witness-ESTABLISHED at the
scanline CODE/CONSUMER scope, rung 5 UNKNOWN.

## W178: mixed-channel sink counterexample to the universal OOB-source ceiling (2026-11-24)

The predicted proof that every OOB destination byte comes from past the source
failed in the pinned sink. `harness/offset-check.sh` over verbatim pinned
slices records copy offsets for six channel/row layouts. FLOAT-before-HALF
with grid `{1024, 2}` copies 4 bytes from source offset 0 to destination
offset 4096; with the in-bounds source filled `0x3c` those bytes appear at
`dst+4096`, 4032 bytes past a 64-byte destination. Two-row FLOAT-first and
three-row mixed grids show the same class. `RESULT PASS bad=0 cases=6`,
`MIXED_RESULT PASS`, evidence sha256
`5861bdd8847e9363f0acee2caf47e55f4e33a607f6fe34148fe29eff2dd929e9`,
byte-stable in three runs. Scope: direct call over two pinned function slices,
harness-supplied bytes, 65536-byte buffers; no wire input or witness verdict
at that scope. File reachability was UNKNOWN at this point and is supplied by
the next section. All-FLOAT file-level results (W160/W163/W170/W172/W174)
stand; the ceiling claim is now scoped to those parts. Grade at that point:
file-level rungs 1-4, W161 witness-ESTABLISHED at scanline CODE/CONSUMER scope,
rung 5 UNKNOWN. Would change mind: a file-driven mixed-channel PoC with chosen
OOB bytes, or a counterexample to the measured copy records.

## W178 file-level extension: chosen bytes at chosen offsets (2026-11-24)

The mixed-channel sink counterexample is reachable from a crafted EXR. A
valid deep+ZSTD baseline with FLOAT "A" before HALF "Z"
(`cases/gen_baseline_deep_mixed.cpp`) is forged by
`cases/make_poc_mixed.py`: 32 samples per row give `split=64` and grid total
192, while the chunk leader declares `unpacked_size=64`, so the vulnerable
guard stays false. The inner stream carries 64 file-chosen bytes (`0x3c`)
for the half block. Through the real pinned `exr_decoding_run()` the sink
copies those 64 in-bounds bytes to destination offset 128 — 64 bytes past the
64-byte `decode.unpacked_buffer`. The guarded allocator reports
`DECODE rv=31` and `changed=128`; gdb shows `0x3c` at `unpacked+128..143`.
Changing the inner byte to `0x5a` puts `0x5a` there; the fixed v3.5.3 build
rejects with `rv=23` and zero changes; the unmodified baseline is clean.
PoC sha256 `484b1c35f66e18db3e263346e100da44a199e4bdf08c0678afe113b042593a52`
(710 bytes), variant `efb6bbd24d9b3c3165f75fe4c2da2f69f0de9ffabf8f3a6ccb6169f8a5af033b`.
Replay `sh lab/openexr2shell-real/harness/mixed-check.sh` -> `RESULT PASS`
with byte-stable normalized evidence (hashes in the file-level report).
Grade: rung 4 at the labeled file-level CODE/CONSUMER scope now includes
file-chosen bytes at chosen offsets; no wire-fed process, pointer/IP,
command or marker. Rung 5 UNKNOWN; this claim unwitnessed — W161 established
only the earlier all-FLOAT file. The prior "OOB bytes are allocator-derived"
claim is now scoped to all-FLOAT parts. Would change mind: a witness
counterexample or an unmodified network-facing consumer reaching this sink.
Both W178 checks replay from clean `git archive HEAD` at `aebf617` with
pinned build trees symlinked in, reproducing all committed evidence hashes.

## W179: unmodified exrcheck -c reaches the mixed-channel chosen-byte sink (2026-11-24)

The W178 file-chosen-byte result is not an artifact of the purpose-built
guarded harness. The unmodified upstream `exrcheck -c` binary built from the
pinned v3.5.2 tree reaches the same pinned `internal_zstd.c:472` sink with the
710-byte mixed-channel PoC: vulnerable ASan reports `READ of size 128` from
past the 64-byte scratch via `exr_decoding_run decoding.c:602` and
`readCoreScanlinePart ImfCheckFile.cpp:1467`; fixed ASan prints `bad`; both
baselines print `OK`; the vulnerable plain build exits 139 (SIGSEGV).

Under gdb the plain build performs two copies at the sink: 128 bytes from
scratch offset 64 (FLOAT row), then 64 bytes from the in-bounds, file-derived
`0x3c` scratch block to `outPtr+128` (HALF row), 64 bytes past the 64-byte
destination. The destination's first 8 bytes change from
`0x20 0x00 ...` to eight `0x3c`. `harness/exrcheck-mixed-check.sh` replays all
six normalized evidence logs and prints `RESULT PASS`, byte-stable in three
working-tree runs. Full commands, hashes and ceiling:
`reports/openexr2shell-file-level.md`, W179 section.

No grade change: rung 4 at the labeled file-level CODE/CONSUMER scope, now also
observed through an unmodified upstream validation tool; still a local path,
no wire, no pointer/control-flow target, no command or marker, rung 5 UNKNOWN.
The new claim is unwitnessed (W161 covered only the older all-FLOAT file).

## W180: file-steered chosen-byte offset (2026-11-24)

The mixed-channel PoC generator now sizes its chunk leader and inner ZSTD
frame to 2N bytes, with N=32 unchanged byte-for-byte. For N=32/64/128 the
vulnerable pinned 3.5.2 harness writes 128/256/512 changed guard bytes and
places the file-chosen HALF block at `decode.unpacked_buffer+4N`
(`+128/+256/+512`), verified with two fill bytes under gdb; the fixed 3.5.3
build rejects all six files with rv=23 and zero changes, and the baseline is
clean. `sh lab/openexr2shell-real/harness/offset-steer-check.sh` ->
`RESULT PASS` three times in the working tree; the earlier mixed-check and
exrcheck-mixed replays still pass. A negative is preserved: changing only N
while keeping the 64-byte inner frame yields rv=23 and no write, so the
frame and leader must scale together. No wire, pointer, command or marker;
this section is unwitnessed and rung 5 stays UNKNOWN. Full hashes, evidence
and ceiling: `reports/openexr2shell-file-level.md` W180.

Clean-archive replay at `9f42ba6` reproduced `RESULT PASS` and all 16
normalized evidence hashes exactly.

## W181: unmodified exrcheck -c with a file-steered chosen-byte offset (2026-11-24)

W179 (N=32, +128) and W180 (N=64/128, +256/+512 under guarded_harness) were
combined: `lab/openexr2shell-real/harness/exrcheck-steer-check.sh` drives
N=64/128 mixed-channel PoCs through the unmodified upstream `exrcheck -c` in
the vulnerable ASan, vulnerable plain and fixed ASan builds. N=64 gives ASan
`READ of size 256` at pinned `internal_zstd.c:472`, fixed rc=1 `bad`, clean
baselines, plain rc=139, and gdb `COPY1 len=256 dst-out=0 src-in=128` /
`COPY2 len=128 dst-out=256 src-in=0` with eight file-chosen bytes at
`outPtr+256` for both fill bytes `0x3c` and `0x5a`. N=128 gives ASan
`READ of size 512`, fixed `bad`, plain rc=134, but gdb aborts inside the sink
before COPY2, so the +512 chosen-byte readback is only W180's guarded-harness
observation. `RESULT PASS` three times byte-stably (aggregate sha256
`555085f1f6491cbc01ee14c1eb231507f0abfd44d68585288ff36925876273fa`); a
clean-archive replay receipt follows. No wire, pointer, command or marker;
grade unchanged, this section unwitnessed, rung 5 UNKNOWN. Full hashes and
ceiling: `reports/openexr2shell-file-level.md` W181.

Clean-archive replay at `0d138b5` reproduced `RESULT PASS` and the aggregate
normalized-output hash `555085f1f6491cbc01ee14c1eb231507f0abfd44d68585288ff36925876273fa`
exactly (15 commit-observed evidence files).

## W182: no code pointer in the C++ deep-path overwrite window (2026-11-24)

W171 mapped the 4096-byte copy onto live glibc chunks only on the flat
`exrcheck` path and found no function pointer or vtable; the advisory's C++
`DeepScanLineInputFile::readPixels` path had not been mapped. A filtered gdb
probe (`harness/cpp-heap-victims.cmd`) stops at the 4096-byte inverse-sort
memcpy in the vulnerable plain build, classifies every 8-byte word in
`[dst,dst+4096)` against the process's executable and main-binary rodata
mappings, walks the heap chunks and scans the live `decode` pipeline structs.
Result: `PTR-HITS total=0`, three chunks (`-16/0x50`, `+64/0x30`,
`+112/0x1490`), and three live pointer fields, all of them the *value*
`decode.unpacked_buffer` at `+0` rather than pointer fields located inside the
window. Two of three chunk headers are clobbered, yet this consumer survives
to a clean `EXR_ERR_INVALID_SAMPLE_DATA` exception (rc=1), not an abort. Fixed
build rejects with `EXR_ERR_CORRUPT_CHUNK`; safe baseline returns 0. No live
control-flow target on either measured path, so the rung-5 pointer-control
option stays closed locally. `RESULT PASS` three times byte-stably; clean
archive replay receipt follows. No wire, chosen bytes, pointer write, command
or marker. Unwitnessed, no grade change, rung 5 UNKNOWN.


Clean-archive replay at `59bce1f`: `git archive 59bce1f
lab/openexr2shell-real` into `/tmp/w182-openexr.e3yu9g`, with the gitignored
`bin-vuln-plain`, `bin-fixed-asan` and `cases/baseline.exr` symlinked from the
live tree, reproduced `RESULT PASS` and the three hashes exactly. Receipt
only, no new claim.


## W183: plant-wide wire-consumer inventory — negative (2026-11-24)

Read-only check (11:06-11:10Z): no lab in this plant has a wire-facing
consumer of pinned OpenEXR 3.5.2. All `exr_decoding_run()` callers
(`harness/flat_harness.c:26,60`, `oiiolab/oiio_flat_consumer.cpp:10-14`,
unmodified `exrcheck -c`) take a local file path. OIIO is configured against
the pinned install (`oiiolab/CMakeCache.txt:576,579`) but never linked (GCC-13
`-Werror=maybe-uninitialized` in `build-oiio-target.log`); the flat-path claim
remains the W173 static negative. The only loopback HTTP consumers in the
plant feed TIFF/ICO to libvips (`lab/frontier/libvips2shell/real/wire.c:43-56,88`,
`imgproxy2shell/provision/http_probe.py:18-27`), not EXR. Rung 5 still needs a
live unmodified wire-fed consumer; a socket wrapper would be synthetic. No
grade change. Full paths and disposition: file-level report W183.


The same wake retried the OIIO build for 900s at `-j2`: zero edges completed
(only `ninja: Entering directory ...` in `oiiolab/oiio-build-w183.log`), two
stuck D-state `cc1plus` children were killed, and `ninja -n` itself exceeded
300s under load ~11-14. No linked OIIO and no dynamic OIIO result. An initial
four-check consolidated replay was cut at 1200s under the same contention;
the retry below completed after cleanup.



W183 replay receipt: all four claim checks passed (`RESULT PASS`, rc 0) in
the working tree and again from `git archive 4a6aa17` into
`/tmp/w183-openexr-clean`; whole-output sha256 pairs matched byte-for-byte,
including `exrcheck-steer` `555085f1f6491cbc01ee14c1eb231507f0abfd44d68585288ff36925876273fa`
from W181. Full hashes and setup: file-level report W183. Author replay only,
not a witness verdict; no grade change.


## W184 (2026-11-24): fully file-chosen out-of-bounds stage

New bounded result, author-only and unwitnessed. A forged mixed-channel deep
EXR with `N=64`, `split=128` and `unpacked_size=256` makes the first
inverse-sort copy (`dst+0`, `src+128`, 256 bytes) fit the destination; the
second copy (`dst+256`, `src+0`, 128 bytes) then lands entirely past it. The
guarded allocator measures all 128 guard bytes changed with the chosen byte
(0x3c and 0x5a variants), and gdb reads back all 128 bytes at
`decode.unpacked_buffer+256` as that byte. Fixed 3.5.3 rejects with
`EXR_ERR_CORRUPT_CHUNK`; baseline guard is clean. Unguarded ASan aborts first
on the initial copy's OOB source READ at pinned `internal_zstd.c:472`, so the
WRITE is measured by guard bytes and gdb, not ASan.

Replay: `cd lab/openexr2shell-real && sh harness/mixed-full-check.sh` ->
`RESULT PASS` 3x, nine byte-stable evidence hashes, aggregate
`d04f151a539362d22d58ec4c4e8c06c4ee0689fd88aa29c5824ba2e7becf946f`.
Generator `cases/make_poc_mixed_full.py`; full method, hashes and caveats in
`reports/openexr2shell-file-level.md` W184. A read-only inventory this wake
also confirmed no existing plant consumer both accepts wire input and decodes
EXR (libvips built with `openexr found NO`, imgproxy probes only tif/ico, OIIO
unbuilt). No grade change: file-level rungs 1-4, rung 5 UNKNOWN, no pointer,
command, marker or witness verdict.


W184 clean-archive receipt (12:50Z): `RESULT PASS`, rc 0, all nine evidence
hashes and the aggregate `d04f151a539362d22d58ec4c4e8c06c4ee0689fd88aa29c5824ba2e7becf946f`
matched the working tree from `git archive aad2c431` with gitignored pinned
source/build/bin trees symlinked. Author replay, not a witness verdict;
grade unchanged.


## W185: no steerable pointer in W184's fully-chosen window (2026-11-24)

Tested whether W184's 128 file-chosen bytes at `dst+256` could replace a live
pointer *field* and steer a later dereference. Negative: the flat harness's
`exr_decode_pipeline_t` is stack-resident, so W171's `LIVE-PTR-INSIDE` lines
are pointer values, not fields; both scratch pointer values are unchanged
after COPY2. In unmodified `exrcheck -c` the same window has `PTR-HITS total=0`
against code/rodata and the process exits cleanly with `bad` (rc 1); fixed
3.5.3 rejects earlier with `DECODE rv=23 EXR_ERR_CORRUPT_CHUNK`. Replay:
`cd lab/openexr2shell-real && sh harness/heap-window-check.sh` -> `RESULT PASS`
3x, six byte-stable evidence hashes. Full method and caveats:
`reports/openexr2shell-file-level.md` W185. No grade change: file-level rungs
1-4, rung 5 UNKNOWN, no pointer/control-flow target, command, marker or
witness verdict.


W185 clean-archive receipt (13:35Z): `RESULT PASS`, rc 0, all six evidence
hashes and the aggregate `56e3a182397fac2e76038d5cd1e6a3bc29f44afd4c10b19d5576d0a26a6c3dcf`
matched the working tree from `git archive 22a8eeec` with gitignored pinned
source/build/bin trees symlinked. Author replay, not a witness verdict;
grade unchanged.

