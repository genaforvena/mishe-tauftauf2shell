# Real-build file-triggered reproduction — W161 (2026-11-23)

This is a new lane beyond the W157 direct-call harness. It uses an actual
libheif build, its real JPEG sequence decoder, its real x265 sequence encoder
plugin and a crafted HEIF file. No network, no socket, no remote target: all
inputs are local files under this lab and all code runs in this wake's process.

## Builds and exact inputs

- Vulnerable source: upstream tag `v1.23.6`, commit
  `f81f28ac014b1c28dee483ac45b72c6b05bc421a`, shallow-fetched into
  `src/libheif-v1.23.6` (git clone --depth 1 --branch v1.23.6). Working tree clean.
- Fixed source: copy of the same tree with pinned `src/9ec655f.patch`
  (SHA-256 `4016424cf9b29bdfa929591095b33d48c1f07edec83a906c19fced15c75f83a4`)
  applied: 14 files changed, 212 insertions, 3 deletions.
- Both builds: cmake 3.28.3, Ninja, g++ 13.3.0, `-DCMAKE_BUILD_TYPE=Debug
  -DBUILD_SHARED_LIBS=OFF -DBUILD_TESTING=OFF -DWITH_EXAMPLES=ON
  -DWITH_GDK_PIXBUF=OFF -DWITH_X265=ON -DWITH_JPEG_DECODER=ON
  -DWITH_JPEG_ENCODER=ON -DWITH_LIBSHARPYUV=OFF` plus
  `-fsanitize=address -fno-omit-frame-pointer -g` in C/CXX/linker flags.
  x265 3.5 (`libx265.so.199`), libde265 1.0.15, libjpeg 80, system libaom.
  Build trees: `/tmp/libheif2shell-vuln-asan`, `/tmp/libheif2shell-fixed-asan`.
- Driver: `reencode_sequence.cc` (SHA-256
  `c89dd64aa3fab4544a4d79e2e49f8f082c1b1c2cd402898850c81c911f056778`).
  It reads a HEIF sequence, decodes each frame as YCbCr 4:2:0, prints the
  decoded width/height/stride, and re-encodes all frames through one x265
  encoder into a new visual sequence track. Pass a third argument
  `decode-only` to stop before encoding.
- Link: `g++ -std=c++17 -g -fsanitize=address -fno-omit-frame-pointer
  -I<src>/libheif/api -I<build> reencode_sequence.cc libheif/libheif.a <the
  absolute codec libraries from ninja -t commands examples/heif-enc> -ldl
  -o /tmp/libheif2shell-reencode-vuln`.
- Reference input: two 512x64 grayscale JPEGs (`evidence/jf_1.jpg`,
  `evidence/jf_2.jpg`) encoded with the pinned build's own
  `heif-enc -S --jpeg jf_1.jpg jf_2.jpg -o reference-same-size.heif`.
  Reference SHA-256 `4da16469703ce5cbc48f7a64f430fb7b1898279df3fcbbca0aa02a5cf583f8dc`.
- Mixed input: `patch_second_sof.py` (SHA-256
  `a48be93623bcaad62ee9a40cf0277599e3e3bebad66f17dff55b93bc8a00d3a8`) flips
  only the second sample's SOF0 height/width from 64/512 to 512/64, so frame 1
  is declared 64x512 while the track and first frame remain 512x64. The
  entropy-coded sample bytes are unchanged. Re-running the script on the
  stored reference reproduces
  `evidence/mixed-mjpeg.heif` exactly: SHA-256
  `12b02138ef60d26bfa68ca72fa1fcb390eb574616138e9f7e545a6b8aee0274e`,
  4262 bytes.

## Observations (all local, pinned vulnerable build)

Decode-only control, `evidence/vuln-real-asan.out` head, rc 0:

```
track declared: 512x64
frame 0 decoded: 512x64 stride=512
frame 1 decoded: 64x512 stride=64
```

Full re-encode, `evidence/vuln-real-asan.out`, rc 1, ASan:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 64 at 0x...440f
#1 HeifPixelImage::extend_padding_to_size(...) pixelimage.cc:644
#2 heif_image_extend_padding_to_size heif_image.cc:403
#3 x265_encode_sequence_frame encoder_x265.cc:1139
#4 Encoder_HEVC::encode_sequence_frame hevc_enc.cc:189
#5 Track_Visual::encode_image track_visual.cc:620
#6 heif_track_encode_sequence_image heif_sequences.cc:622
#7 main reencode_sequence.cc:62
0x...440f is located 0 bytes after a 32783-byte region
allocated by calloc at pixelimage.cc:571 via pixelimage.cc:631
```

The 32783 bytes are `64 rows * 512-byte stride + 16-byte alignment - 1`
(`pixelimage.cc:560`, alignment 16), not the harness's exact 32768 bytes. The
first out-of-bounds byte is at plane offset 32783; the copy continues for 512
rows at stride 512, so ASan stops it on the 65th row. The advisory's
36,879-byte allocation is still an untested claim from a different build.

Same-size safe input (`reference-same-size.heif`): both frames decoded and
encoded, rc 0 with `ASAN_OPTIONS=detect_leaks=0`
(`evidence/vuln-real-safe-noleak.out`). Without that flag LeakSanitizer reports
a pre-existing x265 encoder leak (`evidence/vuln-real-safe-lsan-noise.out`);
that is noise, not the heap overflow, and is preserved as a negative.

Fixed control (patched build, same crafted input, `evidence-fixed/mixed.out`):
decode still reports frame 1 as 64x512, but the encoder rejects it with
`encode: rc=2 sub=0 Invalid input: Unspecified: All frames of a sequence must
have the size of the first frame`, followed by `frame 1 encode FAILED rc=2`.
No ASan report, safe-input control still rc 0. The fixed plugin's guard fires
before the padding call. `rebuild_and_run.sh SOURCE BUILD OUT all` replays all
three cases; it was run on both builds after the driver was corrected to print
encode failures accurately.

## Release-build control (advisory SIGSEGV claim)

Third build of the same pinned source, `/tmp/libheif2shell-vuln-plain`,
`-DCMAKE_BUILD_TYPE=Release -O2`, no sanitizer. Same driver compiled without
ASan. Mixed input: rc 139 (SIGSEGV) after `frame 1 decoded: 64x512 stride=64`
(`evidence/plain-mixed-sigsegv.out`); same-size input: rc 0
(`evidence/plain-safe.out`). gdb batch (`evidence/plain-gdb-backtrace.out`)
shows `Thread 1 received signal SIGSEGV` in
`__memcpy_avx_unaligned_erms`, called from
`HeifPixelImage::extend_padding_to_size` ->
`heif_image_extend_padding_to_size` -> `x265_encode_sequence_frame` ->
`Encoder_HEVC::encode_sequence_frame` -> `Track_Visual::encode_image` ->
`heif_track_encode_sequence_image` -> driver `:62`. The advisory's
release-build SIGSEGV is therefore observed in this build, with the caveat
that this application is a local re-encode driver, not a remote consumer.

## Preserved negatives and discarded paths

- A hand-built ISO BMFF container with a `jpeg` sample entry was rejected:
  "Image sequence track has a chunk that references a non-visual sample
  description." libheif maps `mjpg`, not `jpeg`, to `Decoder_JPEG`.
- The corrected hand-built `mjpg` container failed with "Unexpected end of
  file" (its `mvhd` payload was two bytes too long). Instead of debugging that
  container, the reproducible input above was derived from a file the pinned
  upstream `heif-enc` itself wrote; only a SOF field was changed.
- LeakSanitizer noise from x265 on the safe control (above).
- An early driver revision printed the plane pointer as a stride and omitted
  the track-creation call; both were corrected before these runs.

## W162 heap-neighbour and file-derived chosen bytes

Charter option 2 on the plain Release build. `neighbour/make_pattern_sequence.py`
creates two 512x64 grayscale JPEGs whose pixel value is constant per 8x8
block and varies by block, builds a reference with the pinned `heif-enc -S
--jpeg`, then patches only the second sample's SOF0 to 64x512 (entropy bytes
unchanged). The committed input `neighbour/pattern-mixed.heif` is 5004 bytes,
SHA-256 `8f09b93c85341e9e120e75304379a79df11518cb7def4cc2fc6cdee7da151c1c`;
the generator reproduces that hash exactly from the pinned build's
`heif-enc`. The driver decodes frame 1 as 64x512 stride 64 as before.

`neighbour/gdb_neighbour.cmd` breaks on `calloc(1,32783)`, takes the third hit
(the frame-1 replacement plane), then breaks on each 64-byte row copy whose
destination is at or past `plane+32768`. Save output with:

```
gdb -q -batch -x lab/frontier/libheif2shell/real/neighbour/gdb_neighbour.cmd \
  /tmp/libheif2shell-reencode-plain > .../neighbour/evidence/gdb-neighbour.out 2>&1
python3 .../neighbour/check_neighbour.py .../neighbour/evidence/gdb-neighbour.out
```

Observed (`neighbour/evidence/gdb-neighbour.out`, captured rc 0; checker PASS):
the plane's malloc chunk header at `plane-16` is `0x8021` (32800-byte chunk,
32783 requested). The next chunk's size field at `plane+32792` reads `0x3b41`
before the store. OOB row A copies from the decoded frame-1 plane to
`plane+32768`, row B to `plane+33280`; their 64 source bytes are
`74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8`, derived from the crafted JPEG
blocks. At the eventual SIGSEGV (faulting row at `plane+33792`), gdb reads
exactly those 64 bytes at both destinations; the next-chunk size field is
now `0x9c9c9c9c9c9c9c9c`. With the earlier uniform JPEG the bytes past the
plane were zero and the next chunk size `0x3cc1`, so the observed bytes track
the file, not allocator residue.

This is rung 4 on the real file-triggered path: file-derived, position-
dependent bytes at chosen offsets (row y -> plane+512*y) past the plane, plus
overwritten malloc metadata. The neighbouring object is a **free** chunk, not
a live pointer-bearing object; the process faults after ~16 KB of further
row copies. No pointer target, grooming, marker, live server or wire input
was exercised. Rung 5 stays UNKNOWN.

## W164 bounded one-row overflow: clean copy, abort at free()

Witness #2729's boundary refinement (decoded height must exceed padded
height) suggested a minimal mismatch: patch only the second sample's SOF0
HEIGHT from 512 to 65, width stays 64, using
`neighbour/make_one_row_sequence.py` on the committed `pattern-mixed.heif`.
The generated input is 5004 bytes, SHA-256
`e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67`; the
generator asserts both source and output hashes. Frame 1 decodes 64x65
stride 64; the encoder still pads to the first frame's 512x64.

The copy loop `pixelimage.cc:643-647` now performs exactly one OOB row,
destinations 32768..32831. The following right-edge fill at `:659-666`
repeats the last old-width byte across 32832..33279, reading its source from
offset 33287 — also past the plane. No row-65 memcpy occurs.

Plain Release driver: rc 134 (SIGABRT) with `free(): corrupted unsorted
chunks` (`neighbour/evidence/one-row-plain.out`). The OOB copy itself
completes; the abort comes from the old-plane `free` at `pixelimage.cc:652`,
not from the memcpy. ASan driver: rc 1, the same `WRITE of size 64` at
`pixelimage.cc:644`, 0 bytes after the 32783-byte region
(`neighbour/evidence/one-row-asan.out`). `neighbour/gdb_one_row.cmd`
(`neighbour/evidence/one-row-gdb.out`) reads the plane chunk header `0x8021`,
the OOB row at `plane+32768` with source bytes
`74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8` (the same file-derived pattern as
W162), and the adjacent free chunk's size field `0x3041` -> `0x9c9c...`
with its two bin-link words becoming `0xa8a8...` / `0xb6b6...`.

Negative result: this is NOT a clean-return rung-4 primitive. The adjacent
free chunk's fd/bk words at `plane+32800/+32808` held the live heap address
`0x7ffff6404b20` twice before the store; they are not file-derived pixel
values and preserving them would need heap-layout knowledge. No grooming or
forgery was attempted. One row is therefore already enough to break malloc
metadata: W162's large-copy SIGSEGV is not required for observable
corruption.

## Scope and grade

Observed here: rung 2 (fixed build rejects the same mixed-size file),
rung 3 confirmed memory corruption on the real file-triggered path (ASan
WRITE, exact stack and allocation, overwritten malloc chunk size), rung 4
restricted to file-derived bytes at chosen offsets past the plane (W162,
above), and the advisory's central structural claim — decoder returns
per-frame bitstream dimensions while the x265 encoder keeps first-frame
dimensions. Bytes written past the plane come from the crafted JPEG's decoded
frame, not from a harness-injected buffer. Still absent: network/wire input,
a live server process, a chosen-pointer or control-flow target, a benign
command/marker side effect. Independent W163 replay (witness #2729)
ESTABLISHED W161 and W162 at the labeled local-file/process scope, rungs 1-4,
no counterexample; W164 above was not replayed. The neighbouring object is a
free heap chunk, not a live pointer, so no exploitation path is claimed.
Rung 5 remains UNKNOWN. The advisory's 36,879-byte allocation remains an
untested claim from a different build; this build reports a 32783-byte ASan
region. The release-build SIGSEGV claim is now observed locally (above), not
just quoted from the advisory.
