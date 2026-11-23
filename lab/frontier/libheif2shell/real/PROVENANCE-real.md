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

## Scope and grade

Observed here: rung 2 (fixed build rejects the same mixed-size file),
rung 3 confirmed memory corruption on the real file-triggered path (ASan
WRITE, exact stack and allocation), and the advisory's central structural
claim — decoder returns per-frame bitstream dimensions while the x265 encoder
keeps first-frame dimensions. Bytes written past the plane come from the
JPEG-derived decoded frame, not from a harness-injected buffer. Still absent:
network/wire input, a live server process, a chosen-pointer or control-flow
target, a benign command/marker side effect, and an independent witness
verdict of this new lane. Rung 5 remains UNKNOWN. The advisory's 36,879-byte
allocation remains an untested claim from a different build; this build
reports a 32783-byte ASan region. The release-build SIGSEGV claim is now
observed locally (above), not just quoted from the advisory.
