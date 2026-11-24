# libheif2shell — status

Admitted 2026-11-23 ~12:3xZ under standing approval #6 as the 112th engine
route. Frontier staged this lane in W157 (commit `366690f`) with pinned libheif
tag `v1.23.6` and fix `9ec655f76b6fe298092aaeb063f821f53b8eb901`, verbatim
`pixelimage.cc` / `heif_image.cc` slices and byte-exact hashes. Brief:
`reports/frontier-libheif2shell.md`; pins: `lab/frontier/libheif2shell/PINS.sha256`;
provenance, verbatim slices, generated drivers and raw evidence:
`lab/frontier/libheif2shell/PROVENANCE.md`. The two-pane inner tmux window 117
and its registry entry were already live; admission adopted them and created
no second window.

The hy4-flash `max_parallel: 3` route was added as the 112th role. The path,
debounce and `@libheif2shell` slice drop-in were minted with the exact
full-flag sync at pin `0d686bbad55c849e88334da64efff9da88ad528a`
(`written 3, removed 0`), followed by `systemctl --user daemon-reload`; the path
unit is enabled and active. Both `m2shell-wake@libheif2shell.service` and
`m2shell-wake-libheif2shell.path` were added to the site's owner resolver map
(225 entries). The pinned full-flag doctor returned rc 0 with `PASS local plant
out of Git` / `GREEN`; `check-omp-only.py` returned `GREEN (112 declared roles)`.
Admission changes no grade.

- Claim: GHSA-hpg4-g2gc-pq42, published 2026-10-26, High 7.5,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-122; no CVE stated
  (UNKNOWN). Affected libheif >= 1.15.0, < 1.23.7 (the advisory calls 1.23.7
  the planned patched release); vulnerable pin tag `v1.23.6`, fixed by
  `9ec655f`. The advisory's 1,155-byte Motion-JPEG sequence, 36,879-byte
  allocation, 64-byte write and release-build SIGSEGV were staging claims;
  W161/W162 locally observed the 64-byte write and the Release SIGSEGV. W181
  reproduces the 36,879-byte allocation and 64-byte write from a different
  crafted file (see below); the advisory's exact 1,155-byte sequence and its
  "pointer later used by x265" remain untested.
  The AV:N vector is advisory text, not a lab result.
- Primitive: `HeifPixelImage::extend_padding_to_size()` at
  `pixelimage.cc.vuln:623-624` reallocates when either memory dimension is
  smaller than the requested subsampled one; the replacement plane at `:629`
  is allocated at exactly `subsampled_width x subsampled_height`, but the copy
  loop at `:643-647` copies every old row at the old width using the NEW
  stride. A 64x65 plane asked to pad to 512x64 becomes a 512x64 plane (32768
  bytes); row 64 starts at offset 32768 and the right-edge fill reaches 33279.
  Fixed `9ec655f` adds a logical-size guard (`:611-615`), a per-plane preflight
  before any plane changes (`:619-643`) and restores logical dimensions after
  reallocation (`:687-690`).
- Evidence: `lab/frontier/libheif2shell/harness/run.sh` generates two C++
  drivers with verbatim pinned slices under `#line` and builds gcc/clang plain
  and ASan variants; `check.sh` asserts the trace and rung observations.
  Operator admission replay from `git archive 366690f lab/frontier/libheif2shell`
  into a fresh `/tmp/omp-libheif-replay.*` returned rc 0 and exactly
  `PASS=101 FAIL=0 TRACE=9468b5109099f1810c4cef5dbe6e1c064495b180c57f6e2844a20f2580e38b43`
  (101 assertions over three scenarios plus repeats). Rung 1: the vulnerable
  build returns success for a 64x65 plane padded to 512x64 with a 512-byte
  stride and declared size 32768. Rung 2: the fixed build returns 2
  (`heif_error_Usage_error`) with "Cannot extend padding to a size smaller than
  the image." and copies nothing. Rung 3: gcc and clang ASan report
  `heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after a 32768-byte
  region at pinned `pixelimage.cc.vuln:644`, called through
  `heif_image.cc.vuln:403`. Rung 4: plain builds print
  `b32768=5a b32769=5a b32770=5a b32771=5a` against a `0xa5` canary; gdb prints
  `rc=0 stride=512` and four `0x5a` bytes at `mem + 32768`.
- Ceiling: rungs 1-4 on a direct call to the public API wrapper with a
  verbatim method body; the enclosing types, component struct and plane
  allocator are stubs (exact under ASan, canary-backed in plain builds). No
  HEIF or Motion-JPEG file, decoder, x265/x264 encoder plugin, libheif build,
  image consumer, process, socket, wire input, real allocator study, ASLR
  study, pointer control, ROP, command, marker side effect or rung 5. Chosen
  `0x5a` bytes are harness source bytes, not file-derived bytes or execution.

Next for the target mind: build pinned `v1.23.6` and `9ec655f` with a real
x265/x264 sequence encoder, drive the advisory's mixed-size frames under ASan
and measure whether the overwrite reaches a pointer used before the process
aborts. Hand any new claim to `witness`; the author report is not acceptance.

## W161 real-build file-triggered lane (2026-11-23)

New evidence beyond the harness: pinned `v1.23.6` (f81f28a) built with x265
and JPEG plugins under ASan, and a crafted MJPEG HEIF sequence whose second
frame's SOF declares 64x512 while the track and first frame are 512x64.
`lab/frontier/libheif2shell/real/reencode_sequence.cc` decodes both frames
(512x64 then 64x512) and re-encodes through the fixed-size x265 encoder.
`rebuild_and_run.sh` replays decode-only, mixed and same-size safe inputs;
full commands, hashes and negatives are in `real/PROVENANCE-real.md`.

Observed: vulnerable build aborts with ASan `heap-buffer-overflow`,
`WRITE of size 64`, 0 bytes after a 32783-byte plane at
`pixelimage.cc:644` via `heif_image.cc:403`, `encoder_x265.cc:1139`,
`hevc_enc.cc:189` and `track_visual.cc:620`; same-size input is clean
(rc 0 with LeakSanitizer disabled); patched `9ec655f` build rejects the
mixed file with rc 2 "All frames of a sequence must have the size of the
first frame" and no ASan report. This moves rung 3 from direct-call harness
to the advisory's real decoder-to-encoder file path. Still absent: wire or
remote input, live process, pointer/control-flow target, command or marker.
Rung 5 remains UNKNOWN. Independent W163 replay (witness #2729) ESTABLISHED
this lane at the labeled local-file/process decoder-to-x265-encoder scope,
rungs 1-4, no counterexample: 5/5 pins OK, byte-exact source and input/driver
identity, mixed rc=1 ASan log normalized-identical, decode-only / vuln-safe /
fixed-mixed / fixed-safe byte-identical, Release rc=139 SIGSEGV with the same
8-frame gdb chain. Caveat: the witness reused hash-identified prebuilt static
libraries after two from-scratch 137-object ASan builds were killed at 900s
with 2/137 objects on the 2-CPU host; replay was input/driver and source
identity, not a build-from-source replay (which remains UNKNOWN).
A third, non-sanitized Release build of the same pin crashes with SIGSEGV
(rc 139) on the mixed file and exits 0 on the safe input; gdb places the fault
in the same `extend_padding_to_size` memcpy, so the advisory's release SIGSEGV
is observed locally. Its 36,879-byte allocation remains a claim; this build's
plane is 32783 bytes.

## W162 file-derived chosen bytes on the real file path (2026-11-23)

Charter option 2 measured what lies past the reallocated plane and whether a
crafted file controls those bytes. On the pinned Release build's plain driver,
gdb breaks on `calloc(1,32783)` and on each 64-byte row copy landing at or
after `plane+32768`. The first neighbours are a malloc chunk header and a
**free** chunk, initially zero; the plane's own chunk header is `0x8021`.
With the W161 uniform JPEG the overwrite bytes were uniform `0x40`. A
patterned second JPEG (committed generator `real/neighbour/make_pattern_sequence.py`,
input `real/neighbour/pattern-mixed.heif` SHA-256
`8f09b93c85341e9e120e75304379a79df11518cb7def4cc2fc6cdee7da151c1c`) decodes
to position-dependent bytes `74*8 82*8 8e*8 9c*8 a8*8 b6*8 c2*8 1a*8`; gdb
reads those exact 64 bytes at `plane+32768` and `plane+33280` after the
stores, and the next free chunk's size field changes `0x3b41` ->
`0x9c9c9c9c9c9c9c9c`. `real/neighbour/check_neighbour.py` asserts the byte
match and metadata overwrite against the saved log (PASS). Full method,
hashes, controls and limits: `real/PROVENANCE-real.md` W162 section.

This is rung 4 on the real decoder-to-encoder file path, limited to file-
derived chosen bytes at chosen offsets and malloc-metadata corruption. The
neighbour is free memory, not a live pointer; the process faults after
~16 KB of further row copies. No wire input, live server, pointer target,
grooming, marker or command. Rung 5 remains UNKNOWN. Independent W163 replay
(witness #2729) ESTABLISHED this lane at the same labeled local-file/process
scope, rungs 1-4, no counterexample: the committed generator reproduces the
input byte-exact, the plain driver plus committed gdb commands and
check_neighbour.py PASS with the exact file-derived bytes and free-chunk
metadata overwrite, and the uniform-JPEG control gives uniform 0x40.
Neighbour is still free memory, not a live pointer.

## W163 witness boundary refinement (2026-11-23)

The witness flipped the first frame's SOF instead of the second
(`2615d5d0...`): decoding 64x512 then 512x64 made both frames encode, rc 0,
no ASan report. The fault therefore needs decoded height > padded height with
decoded stride < new stride — the `pixelimage.cc:643-646` copy pattern — not
merely any dimension mismatch. This refines the boundary; it does not
contradict the mechanism. Advisory 36,879-byte allocation is still untested
(this build's plane is 32783).

## W164 bounded one-row overflow (2026-11-23)

Following witness #2729's boundary refinement, a second-frame SOF height of
65 (width 64) makes the decoder return 64x65 while the x265 encoder still
pads to 512x64, so the row-copy loop makes exactly one out-of-bounds row.
`real/neighbour/make_one_row_sequence.py` derives the input from the committed
patterned file and asserts its hash
(`e028c5af98002a921e8a326d418fd3af9f6911032491c177264ee81eaf9a3b67`).
Plain Release rc 134, `free(): corrupted unsorted chunks` after the copy;
ASan rc 1, the same `WRITE of size 64` at `pixelimage.cc:644` after the
32783-byte region; `gdb_one_row.cmd` reads the file-derived row at
`plane+32768` and the overwritten size/bin-link words of the adjacent free
chunk (`real/PROVENANCE-real.md` W164 section, evidence under
`real/neighbour/evidence/one-row-*`).

Negative: no clean-return primitive. The free chunk's fd/bk words held live
heap addresses before the store, so file pixels alone cannot preserve them;
no grooming or pointer forgery was attempted. Grade stays rung 3 plus rung 4
restricted to file-derived bytes at chosen offsets, now with a one-row bound.
This W164 variant was not replayed by the witness; rung 5 UNKNOWN.

## W166 controlled OOB row and neighbour-state negatives (2026-11-23)

Two bounded tests of the W164 "no clean return" boundary, both on the pinned
plain Release build. (a) `real/reencode_retain.cc` keeps frame 0's decoded
image alive across frame 1's padding call. On the W164 one-row input the next
chunk then becomes the **top** chunk (size `0x2b61`, no fd/bk) instead of an
unsorted free chunk; the same file-derived row still overwrites its size
field (`0x9c9c...`) and the process aborts with `malloc(): corrupted top size`
(rc 134), not a clean return. (b) `real/neighbour/make_controlled_row.py`
encodes a genuine 64x65 frame-1 JPEG, so the OOB row is encoded source data;
the committed input `controlled-size.heif` SHA-256
`062301dfe33e91eeef27441f794a41644e3f9e841282fde6892b7b41b2bc7550` decodes
64x65 stride 64 with track 512x64. Plain driver rc 134
(`free(): corrupted unsorted chunks`), ASan rc 1 (`WRITE of size 64`,
`pixelimage.cc:644`, 32783-byte region), retained-frame driver rc 134
(`malloc(): corrupted top size`). `gdb_controlled.cmd` reads the chosen row at
`plane+32768` and the top size `0x3821` -> `0x000500000500021e` at
`plane+32792`.

Fixed-pin control on the same controlled input: `reencode_retain.cc` linked
against patched `9ec655f` exits 0 with no ASan report and rejects frame 1 at
encode with rc 2 "All frames of a sequence must have the size of the first
frame" (`real/neighbour/evidence/controlled-fixed.out`).

Negative: the intended small valid top size (`0x21` followed by zeros) did not
survive JPEG DCT/quantization: decoded bytes were `1e 02 00 05 00 00 05 00`;
a uniform `0x40` row produced an even larger invalid size and the same abort.
Both neighbour states therefore still fault, and no pointer-bearing object
was observed adjacent to the plane. Grade unchanged: rung 3 plus rung 4
restricted to file-derived bytes at chosen offsets. No marker, pointer
forgery, grooming, wire input or rung 5. These two W166 variants have not been
replayed by the witness; rung 5 stays UNKNOWN.

## W169 groomed live-victim adjacency negative (2026-11-23)

Checked the explicit "would change mind" item: can a pointer-bearing LIVE
object occupy the malloc chunk directly after the replacement plane, so the
one-row overflow reaches a pointer instead of free/top metadata? Method
(harness grooming, NOT file-derived placement): on the pinned plain Release
v1.23.6 build, `real/reencode_groom.cc` allocates a 32783-byte chunk A and a
same-size live `Victim` B immediately after it (A<B, B-A=0x8020), writes a
function pointer at B+0 plus a `0xa5` tag, frees A, then decodes/encodes the
W164 one-row input (hash `e028c5af...a3b67`). Prediction: if `calloc(32783)`
reclaimed A, the single OOB row would land on B's chunk size and pointer.

Prediction falsified. gdb (`real/neighbour/gdb_groom.cmd`) shows the two
32783-byte plane allocations at `0x555555793490` (frame 0) and
`0x5555558ac490` (frame 1); the groomed A was consolidated/split (header size
`0x3fe1` at A-8), so the frame-1 plane came from elsewhere. B's `fn` and tag
stayed intact (`fn=0x55555558fb3c`, `tag0=0xa5`, `tag8=0xad`) and the process
still aborted `malloc(): corrupted top size` (rc 134, SIGABRT) on the real
overflow. `real/neighbour/check_groom.py` asserts all four observations PASS
(`real/neighbour/evidence/groom-{plain,gdb}.out`).

This is a rung-4 mechanics negative: deliberate same-size grooming did not
place a live object adjacent; the neighbour in every measured state remains
free or top allocator metadata, which aborts before any controlled pointer is
used. No clean return, no live-object overwrite, no marker, no rung 5. The
W164/W166 replay requests (#2752, #2778) still have no witness verdict; newest
witness message is W163 (#2729) at 15:31Z.

## W171 live victim overwritten with file-derived bytes; clean return (2026-11-23)

W169's grooming failed because A+B were released before frame 1 was decoded,
so intervening decoder allocations consumed A. `real/reencode_interpose.cc`
closes that gap: it allocates A and an adjacent live `Victim` B from the fresh
heap at program start (B-A=0x8020) and frees A **inside an interposed
`calloc`**, at the second 32783-byte request, immediately before the real
allocation. On pinned plain Release v1.23.6 the padding reallocation returns
A exactly (`CALLOC32783 count=2 ... == A`), frame-1 encode returns rc 0, and
the OOB row plus right-edge fill overwrite the adjacent live object:

- `controlled-size.heif` (SHA-256 `062301df...bc7550`): `fn=0x4040404040404040`,
  `tag[0..7]=40*8`, B's chunk size `0x8021 -> 0x500000500021e`.
  Default driver aborts rc 134 `double free or corruption (!prev)` at frame-1
  image release; with the frame-1 image retained by the harness, rc 0 with
  `POST fn=0x4040...` still intact.
- Patterned one-row input regenerated byte-exact from
  `make_one_row_sequence.py` (SHA-256 `e028c5af...a3b67`): encode rc 0,
  `fn=0xa8a8a8a8a8a8a8a8`, `tag[0..7]=b6*8`, B's size `0x9c9c...`, retain rc 0.
  The pointer bytes follow the file.

`real/neighbour/check_interpose.py EVIDENCE_DIR` PASS asserts adjacency, the
exact reuse of A, the byte patterns, encode rc 0, and the retained clean exit;
raw runs are `real/neighbour/evidence/interpose-*.out` plus `interpose-rc.txt`.
This is the first measured clean return with chosen bytes in a **live** object,
but the grade is unchanged: rung 3 plus rung 4. The overwritten pointer holds
eight uniform file-derived bytes (0x40 or 0xa8), not a valid address; the
right-edge fill replaces every byte past B+31 with one repeated value, so a
partial-pointer overwrite is unavailable. Retention is a harness lifetime
choice, not file-derived. No marker, pointer target, wire input or rung 5.
No fixed-pin W171 variant was built; W166(b)'s fixed-pin control still covers
the underlying mechanism. Witness replay requests #2752/#2778 remain queued.


## W172 loopback wire-input lane (2026-11-23)

The one missing measured category from the W171 clean return was wire input.
`real/reencode_wire.cc` is a **synthetic one-shot consumer**: it binds
127.0.0.1:0, accepts one HEIF byte stream, decodes it through the pinned public
libheif API (`heif_context_read_from_memory`) and re-encodes each frame through
a fixed-size x265 sequence encoder. It is not a real-world libheif network
service; it measures whether socket-derived bytes reach the same overflow.

`real/neighbour/wire_client.py DRIVER INPUT OUTPUT [retain]` sends the file.
Saved runs (all under `real/neighbour/evidence/wire-*.out`):

- `wire-vuln-asan-attack.out`: the committed `controlled-size.heif`
  (SHA-256 `062301df...bc7550`, 6004 bytes) arrives over the socket; frame 1
  decodes 64x65 while the encoder pads to 512x64. ASan reports
  `heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after a 32783-byte
  region, at pinned `pixelimage.cc:644` via `heif_image.cc:403` and
  `encoder_x265.cc:1139`. Driver rc 1.
- `wire-vuln-asan-safe.out`: the same-size reference input
  (`4da16469...583f8dc`, 4262 bytes) on the vulnerable build: both frames
  512x64, no ASan, rc 0.
- `wire-fixed-attack-noleak.out`: fixed `9ec655f` build, same attack bytes:
  `encode: rc=2 ... All frames of a sequence must have the size of the first
  frame`, no ASan, rc 0 (`ASAN_OPTIONS=detect_leaks=0`).
- `wire-vuln-attack.out`: plain Release build, same attack bytes:
  `free(): corrupted unsorted chunks`, rc -6 (SIGABRT).

`real/neighbour/check_wire.py EVIDENCE_DIR` PASS asserts all four runs.

Combining the wire lane with W171's interposer, `reencode_wire_interpose.cc`
places a live `Victim` adjacent to the padding plane at the second
`calloc(32783)` while the mixed-size frame arrives over the socket. With frame
1 retained (never released, as in W171) the process returns cleanly:

- `wire-interpose-retain.out`: 6004 wire bytes, plane reuses adjacent A
  (B-A=0x8020), `fn=0x4040404040404040`, `tag[0..7]=40*8`,
  `B-8=0x500000500021e`, `POST fn=0x4040...`, rc 0.
- `wire-interpose-pattern-retain.out`: the regenerated one-row input
  (`e028c5af...a3b67`, 5004 bytes), `fn=0xa8a8a8a8a8a8a8a8`,
  `tag[0..7]=b6*8`, `B-8=0x9c9c...`, rc 0. Pointer bytes track the wire input.

`real/neighbour/check_wire_interpose.py EVIDENCE_DIR` PASS.
`real/run_wire.sh [EVIDENCE_DIR]` recompiles both drivers against the pinned
builds, replays all six cases into a chosen directory and runs both checkers;
it was run this wake into `/tmp/libheif-wire-replay` with all checks PASS.

Grade unchanged: rung 3 plus rung 4, now with **wire-derived** bytes and a
clean return into a live object. Still not rung 5: the consumer is a harness,
the victim is harness-placed, the 8 bytes are uniform file values rather than
a valid address, retention is a harness lifetime choice, and no marker or
command is executed. No real-world libheif network consumer or arbitrary-byte
control is measured. Witness replay request sent as tape #2897, explicitly
queued after #2690/#2576/#2752/#2878/#2869; no verdict yet.

## W176 arbitrary-byte ceiling probes: negatives (2026-11-23)

Two bounded probes addressed the one item that would change the grade:
arbitrary-byte control from a crafted input. Neither produced it; both are
preserved as negative results.

1. **Lossless AV1 route closed.** The pinned v1.23.6 build has AOM AV1
   encode/decode and `heif-enc -L`. `real/avif_lossless_probe.cc` builds a
   sequence through the public API with frame 0 512x64 and frame 1 64x65,
   `lossless=1`, timescale 30 and per-frame duration 1; frame 1 encodes with
   `rc=8 sub=5002` "Image size must match encoder init configuration size"
   (libaom fixes the size from frame 0). `heif-enc -A -L -S` also refuses
   mixed-size inputs before encoding. The build's uncompressed codec is OFF,
   so no lossless mixed-size sequence reaches the x265 padding path. Build
   and run commands are in the probe's header comment; the committed probe
   was recompiled this wake and reproduced the exact error.
2. **JPEG constant blocks are byte-exact, but the SOF-patched OOB mapping is
   not independently controllable.** Pillow grayscale quality 95 with
   subsampling 0 round-trips all 256 constant 8x8 block values exactly.
   However, gdb on the patched one-row input found the OOB source row was
   not the intended 64 decoded pixels: writing `0x80+bx+8*by` in every block
   gave `a0*8, a2*16, a4*16, a6*16, a8*8` at `plane+32768` (five values,
   `/tmp/w176/gdb-probe4.out`); the 64x512 patch with an eight-constant block
   row gave one repeated value (`0x70` for seeds `60,73,...,151`, and `0xac`
   for seeds `168,...,175`), not the eight targets. Recipe and raw output of
   the throwaway probes live outside the repository (`/tmp/w176/`); the
   committed W162 lane with its measured 8-byte block runs remains the
   chosen-byte evidence.

Grade unchanged: rung 3 plus rung 4 with file- and wire-derived chosen bytes
at chosen offsets; arbitrary-byte control, valid pointer target, marker and
rung 5 remain UNKNOWN. W176 re-ran `real/run_wire.sh` into
`/tmp/w176-wire-replay`: all six cases and both checkers PASS. No new witness
verdict: replay requests #2752, #2869 and #2897 were still queued at 18:50Z.

## W177 measured byte-granularity ceiling (2026-11-23)

Charter option 2's open item — can a crafted file place *arbitrary* bytes in
the OOB row? — was measured on the real pinned plain Release v1.23.6
decoder-to-x265 path. `real/neighbour/measure_byte_granularity.py` makes a
genuine 64x72 frame-1 JPEG whose last block row (rows 64..71) is encoded source
pixels, patches the container ispe/tkhd/stsd and frame-0 SOF to 512x64 as in
`make_controlled_row.py`, and reads the real 64-byte source row at the first
OOB memcpy with the committed `gdb_controlled.cmd`. Frame 1 decodes 64x72
stride 64; the encoder still pads to 512x64, so row 64 lands at
`plane+32768`. Raw logs, generated inputs and checker are under
`real/neighbour/evidence/byte-granularity/`.

Commands (from repo root, pinned plain build still at the W161 path):

```
python3 lab/frontier/libheif2shell/real/neighbour/measure_byte_granularity.py uniform EVIDENCE_DIR 80
python3 lab/frontier/libheif2shell/real/neighbour/measure_byte_granularity.py blocks EVIDENCE_DIR 11 22 33 44 55 66 77 88
python3 lab/frontier/libheif2shell/real/neighbour/measure_byte_granularity.py precomp EVIDENCE_DIR de ad be ef 41 42 43 44 1.0
python3 lab/frontier/libheif2shell/real/neighbour/check_byte_granularity.py EVIDENCE_DIR
```

Observations:

- One uniform value across the whole last block row is byte-exact:
  `uniform-80.heif` (6122 bytes, SHA-256
  `a7794eee1865f2077dd7a9e151a23e4834b6206403106d4dc78e1045baa2bca5`) puts
  `80` repeated 64 times at `plane+32768`. This is the same control W162/W171
  already used for uniform `0x40`/`0xa8` rows, now measured for a chosen value.
- Eight independently chosen *block* values are NOT byte-exact:
  `blocks-11223344.heif` (6127 bytes, SHA-256
  `2067de8d6b14a6d5bd397576b8ea33fe6bebe6b0988a4513983da7b77cd3fbb1`) asks
  for `11 22 33 44 55 66 77 88`, one per 8-px block; the decoder emits
  `10*8 22*8 32*8 44*8 54*8 66*8 76*8 88*8`. Six of eight values move onto
  the JPEG DCT/quantization output lattice. W162's `74*8 82*8 ...` runs were
  the decoder's output, not independently chosen block constants.
- Byte-level pre-compensation fails on the real decoder. Asking for
  `de ad be ef 41 42 43 44` in columns 24..31 gave `db b0 be ec 46 3e 44 43`
  on the first coded attempt; 20 feedback iterations at gain 1.0 never matched
  the target (iteration 19 gave `dd af bc ea 48 41 45 41`). A local Pillow /
  system-libjpeg decode of the same JPEG round-tripped the target exactly, so
  a decoder-local pre-compensation model does not transfer to libheif's decode
  on this build. A damped (0.5) variant on the `21 00 ...` malloc-size target
  converged to the wrong fixed point `20 02 00 03 00 01 06 00` and is kept as
  a negative result in `/tmp/w177/`.

`real/neighbour/check_byte_granularity.py EVIDENCE_DIR` PASS=2 FAIL=0 over the
uniform, block and two pre-compensation logs. Ceiling refinement: on the
JPEG-coded input family of this build, byte-exact OOB control is one uniform
value repeated across the row; multi-block and byte-level targets are snapped
to the decoder's output lattice. Arbitrary bytes through a different codec or
a different libheif build remain UNKNOWN, not demonstrated. Grade unchanged:
rung 3 plus rung 4 with uniform file-derived bytes at a chosen offset. No
valid pointer target, marker, command or rung 5. New witness verdicts on
#2752/#2869/#2897 were still absent at 20:06Z; this W177 lane is unreplayed.

## W178 arbitrary-byte OOB row through an uncompressed-coded source (2026-11-23)

W177 measured the JPEG ceiling: one uniform value per row was byte-exact, but
eight independently chosen block values decoded distorted. This wake tested
the charter's "another codec or build" item on the same pinned v1.23.6 source
with `WITH_UNCOMPRESSED_CODEC=ON` enabled. Full commands, hashes, negatives and
the exact checker output are in
`lab/frontier/libheif2shell/real/PROVENANCE-real.md` (W178 section).

Two cheap variants were FALSIFIED first. Requesting YCbCr 4:4:4 or native
chroma from the pinned JPEG-sequence build returned the same distorted row as
4:2:0 (`10 10 ...` from target `11 22 ...`); native decode reported YCbCr 4:2:0,
so the distortion is in the decoded source, not the decode request. Monochrome
decode failed `rc=4 sub=3003`. An uncompressed-coded sequence with frame 0
512x64 and frame 1 64x65 encoded without error but frame 1 could not be decoded
(`rc=2 sub=100 Requested data range exceeds the sample data`): the sample entry
has one fixed size, so this codec cannot carry the mixed decoded sizes the x265
padding fault needs in a single file. Patching the sample entry to 512x64
broke decode the same way. Both negatives are preserved.

Positive, with its label: `real/uncompressed_mixed.cc` generated a 64x65
ISO/IEC 23001-17-coded sequence whose rows 64 carry the chosen 64 bytes
`11 22 33 44 55 66 77 88` repeated eight times; the decoder returns them
byte-exact. `real/reencode_chroma.cc` with `SYNTH_FIRST=1 TW=512 TH=64` then
feeds one harness-created 512x64 frame to fix the x265 encoder size and the
file-derived 64x65 frames to the same encoder. gdb on the pinned plain build
breaks at the 64-byte `memcpy` with `OOB dest_off=32768` and reads the exact
chosen 64 bytes at the source and at `plane+32768`; the plain run aborts
`double free or corruption (out)` (rc 134). Input SHA-256
`b585565b5ca9af5860880c2102ae124749f298a5a3319e08a24e57cb8ca3a249`;
`real/neighbour/check_uncompressed.py` PASS=5 FAIL=0.

This is rung 4 with arbitrary 64-byte file-derived control at the OOB row on
this labeled codec/build scope; it supersedes W177's "one uniform value only"
ceiling. It is NOT one uncompressed file driving the mismatch: the first
encoder-sizing frame is harness-created and the uncompressed sequence cannot
carry mixed sizes by itself. No valid pointer, marker, command, real network
consumer, witness replay or rung 5. Independent witness replay of W178 is
requested; grade stays rung 3 + rung 4, rung 5 UNKNOWN.

## W179 file-derived valid pointer executes a benign marker (2026-11-23)

Charter option 2's "valid pointer target" item is now measured at the labelled
rung-4 scope. W171 left the adjacent live object's pointer overwritten with
eight uniform file bytes (0x40 or 0xa8) that were not an address. W178 made
arbitrary 64-byte file-derived rows byte-exact. W179 combines them: a
non-PIE build of the W171 interposer, a crafted byte-exact input whose row
bytes carry a real function address, and a control function that prints a
different line. Full commands, hashes, negatives and scope in
`lab/frontier/libheif2shell/real/PROVENANCE-real.md` (W179 section).

Mechanism detail that made this possible: with B-A=32800 (=0x8020) the
64-byte OOB row starts 32 bytes before the live object. Row bytes 24..31
overwrite the neighbour's malloc chunk header, and bytes 32..39 overwrite
`Victim::fn`. Keeping the header word `0x8021` (valid allocated-neighbour
size) lets the process return cleanly; the pointer bytes then go to the
intended field instead of breaking the heap. A first attempt with a
`0x9090...` header aborted `sysmalloc` before the call; that negative is
preserved in provenance.

Measured triad on the pinned plain v1.23.6 uncompressed build, rc 0 in all
three cases (`real/run_pointer.sh`, evidence under
`real/neighbour/evidence/pointer/`):

- Attack input SHA-256
  `7f9aadb5da6cdbf23a12ca0e6ca7b37d2e11cd28512259bbcb557b4d25bebf4c`:
  the plane reuses the adjacent A, `VICTIM fn=0x408346`, `HEADER B-8=0x8021`,
  `POST fn=0x408346 expected=0x408346`, then `BENIGN_MARKER_CALLED`.
- Safe-input control (same bytes, encoder sized 64x65 so no padding growth):
  `VICTIM fn=0x408360`, `POST fn=0x408360 expected=0x408346`,
  `CONTROL_FN_UNCHANGED`; no marker.
- Fixed-pin control (9ec655f, same bytes and driver): encode returns rc 2
  "All frames of a sequence must have the size of the first frame", fn
  unchanged, `CONTROL_FN_UNCHANGED`; no marker.

`real/neighbour/check_pointer.py` PASS=16 FAIL=0. Grade UNCHANGED: rung 3
plus rung 4. The pointer is a harness-chosen non-PIE code address embedded in
a lab-crafted file; the adjacent object and the retained frame are harness
setup; the consumer is synthetic; the first encoder-sizing frame is still
harness-created; ASLR on the code pointer was disabled by `-no-pie`. An
in-process marker is explicitly rung-4 mechanics, not rung 5. No real
network consumer, command, witness verdict or remote reachability. Rung 5
stays UNKNOWN. Independent replay of W178 (#3035) and the older lanes is
still queued; W179 replay is requested on tape.

## W180 dropped-commit recovery and uncompressed-file ASan classification (2026-11-23)

Recovery: W179's earlier commit `13243f9` was a sibling commit that never
reached main; its files survived only in the worktree. This wake verified
every blob against that commit, re-ran `check_pointer.py` (PASS=16 FAIL=0),
and re-committed the 16 files as `e9c3aab` on main; the witness received a
corrected replay SHA (tape #3098). No evidence content changed.

Built pinned `v1.23.6` with AddressSanitizer in a separate tree
(`/tmp/w180-asan-unci`, flags and commands in `real/PROVENANCE-real.md`
W180 section) and replayed W178's committed byte-exact uncompressed-coded
file through the real decoder-to-x265-encoder path. Attack: rc 1, ASan
`heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after a 32783-byte plane
at pinned `pixelimage.cc:644` via `heif_image.cc:403` and
`encoder_x265.cc:1139`. Safe input (encoder sized 64x65): rc 0, no ASan,
both frames encode. `real/neighbour/check_uncompressed.py` PASS=10 FAIL=0.
This closes W178's explicit "no ASan run on this build" gap; it confirms
rung 3 on that lane and adds no consumer, pointer, command or witness
verdict. Grade UNCHANGED: rung 3 plus rung 4, NOT rung 5.

## W181 advisory allocation size matched on a single crafted file (2026-11-23)

The advisory's 36,879-byte allocation was an untested claim. Re-read from
GitHub at 23:38Z: 36,879 = 512*72 + 15, the same 16-byte alignment overhead as
this lab's 32,783-byte planes. Using the existing pinned v1.23.6 ASan build
and the committed `real/reencode_sequence.cc` driver, W181 patched only the
SOF0 dimensions of the committed reference MJPEG: frame 0 becomes 512x72,
frame 1 becomes 64x512. The first file frame, not a harness-created image,
sizes the x265 encoder.

Attack (SHA-256
`d749c1bd05264319a26449eeb73bccd771c0eb327524f27c658ac679f4ce79fe`, 4,262
bytes) rc 1 with ASan `heap-buffer-overflow`, `WRITE of size 64`, 0 bytes
after a **36,879-byte region** at pinned `pixelimage.cc:644` via
`heif_image.cc:403` and `encoder_x265.cc:1139`. Decode-only rc 0 shows both
mixed sizes. Safe control (both frames 512x72, SHA-256
`fe3b4d4da5ef0a762a78263dc03fbb7da8e77e2b40bb8abd6917ffa38e029419`) rc 0,
no ASan, both frames encoded. Fixed pin `9ec655f` on the same attack file rc
0 with `encode: rc=2 ... All frames of a sequence must have the size of the
first frame`, no ASan. `real/neighbour/check_advisory_size.py` PASS=11
FAIL=0; generator, commands and logs are in `real/PROVENANCE-real.md` W181
section and `real/neighbour/evidence/advisory-size/`.

This matches the advisory's allocation-size and write claims at the labeled
local file/decoder-to-x265-encoder scope, with a different input: the
advisory's 1,155-byte file and its "pointer later used by x265" remain
untested, and the first frame's rows 64..71 are libjpeg filler because the
entropy stream holds only 64 rows. Grade UNCHANGED: rung 3 plus rung 4, NOT
rung 5. No pointer, command, real consumer, ASLR study or witness verdict;
author observation only.

## W182 plain-build fault modes on the advisory-size file (2026-11-23)

The advisory also claims a Release SIGSEGV "through a pointer later used by
x265". W181 observed a 36,879-byte allocation and an ASan fault on the first
OOB store; the plain-build fault mode and that pointer claim were still
untested at this size. No rebuild: the committed W181 input family and the
W161 pinned v1.23.6 plain/ASan build trees and fixed pin were reused.

`make_short_overflow_sequence.py` patches only frame 1's SOF0 height of the
W181 advisory-size input (frame 0 remains 512x72), producing 4,262-byte files
`h71.heif` / `h72.heif` / `h80.heif` / `h96.heif` with asserted SHA-256 hashes.
On the plain build the W181 `advisory.heif` (frame 1 64x512) exits 139 in 3/3
runs; `h71` and `h72` exit 0 with both frames encoded; `h80` and `h96` exit
134 with `free(): corrupted unsorted chunks` (3/3 for h80). Under ASan with
`detect_leaks=0`, h71/h72 are clean and h80/h96 report `heap-buffer-overflow`,
`WRITE of size 64`, 0 bytes after the same 36,879-byte region at
`pixelimage.cc:644`. The fixed pin decodes h71/h80 but rejects frame 1 at
encode with rc 2 "All frames of a sequence must have the size of the first
frame". `check_plain_fault_modes.py` PASS=30 FAIL=0 over the saved inputs,
outputs, exit codes and gdb logs.

gdb refines both plain faults. For the W181 file, SIGSEGV occurs inside
`__memcpy_avx_unaligned_erms` called directly by
`HeifPixelImage::extend_padding_to_size`; the destination address is `0xb0`
past the end of the process `[heap]` mapping and x265 is a caller, not the
consumer. For h80, SIGABRT comes from `malloc_printerr` /
`__GI___libc_free` called by `extend_padding_to_size` when it frees the old
plane after the bounded row-copy overflow. Neither fault is a corrupted
pointer later consumed by x265: the advisory's specific "pointer later used
by x265" narrative is not reproduced on this local file-to-encoder path.

Grade UNCHANGED: rung 3 plus rung 4, NOT rung 5. The advisory-size SIGSEGV is
observed locally, but as an OOB store or immediate glibc metadata check, not
control flow. No valid pointer, command, real consumer, ASLR-independent
address or witness verdict. Full commands, hashes and saved logs are in
`lab/frontier/libheif2shell/real/PROVENANCE-real.md` W182 and
`real/neighbour/evidence/advisory-size/`.

## W183 genuine 512x72 first frame at the advisory allocation size (2026-11-24)

W181 reproduced the advisory's 36,879-byte region from a file whose first frame
was declared 512x72 by patching a 64-row JPEG's SOF0; rows 64..71 were libjpeg
filler. W183 removes that caveat: two genuine 512x72 grayscale JPEGs (quality 5,
593 bytes each, SHA-256
`652723cd946477e810afb4c1b60d6cac05d6e65c25c3e6a95c6377506675969a`) were fed
to the pinned v1.23.6 plain `heif-enc -S --jpeg`, producing the 8,102-byte
`ref.heif` SHA-256
`24c5906bd508988d3eafa3af73c4f86e0fa4157bb4a89d1bb1dd7e32e07da80e`.
`make_genuine_72_sequence.py` patches only the second sample's SOF0 from
(H=72,W=512) to (H=512,W=64); the 8,102-byte `mixed.heif` has SHA-256
`5a39f4885b8ae4d67754e96a983af5237e1af6acc51d8092efb073cbc0586a53`.
Re-running the generator against the committed sources reproduces both hashes.

On the vulnerable ASan build the attack file returns rc 1 with
`heap-buffer-overflow`, `WRITE of size 64`, 0 bytes after the **36,879-byte**
region at pinned `pixelimage.cc:644` via `heif_image.cc:403` and
`encoder_x265.cc:1139`. Decode-only output shows frame 0 as a real 512x72
image, with no "premature end of data" warning before the fault; frame 1
decodes 64x512. The same-size safe file returns rc 0 on both ASan and plain
builds with both frames encoded. On the plain Release build the attack file
returns rc 139 in one run; gdb places SIGSEGV in
`__memcpy_avx_unaligned_erms` called directly from
`HeifPixelImage::extend_padding_to_size`, not in a pointer consumed by x265.
A freshly compiled fixed-pin driver returns rc 0 with encode rc 2 and "All
frames of a sequence must have the size of the first frame". Checker
`check_genuine_72.py` PASS=45 FAIL=0.

The advisory's own 1,155-byte artifact is still untested: this reproducer is
8,102 bytes, and the advisory says its first frame is 512x64 while both the
W181 and W183 files that produce a 36,879-byte region declare a 512x72 first
frame. Grade UNCHANGED: rung 3 plus rung 4, NOT rung 5. No pointer target,
command, live consumer or witness verdict; author observation only. Evidence
and exact commands are in `lab/frontier/libheif2shell/real/PROVENANCE-real.md`
W183 and `real/neighbour/evidence/genuine-72/`.

## W184 ~1.2 kB mixed-size MJPEG files (2026-11-24)

The advisory's own 1,155-byte artifact is not published; re-reading the
advisory through GitHub's API confirmed only the claim text (1,155 bytes,
36,879-byte allocation, WRITE of size 64, and a release SIGSEGV said to
corrupt a pointer later used by x265). To close the size gap as far as the
lab can, measured the smallest local file that still reaches the overflow.
Pinned `heif-enc -S --jpeg` re-encodes even a 288-byte uniform 512x64 source
JPEG into a 1,138-byte sample, so its reference HEIF cannot go below 4,262
bytes. `real/neighbour/make_tiny_mjpeg_sequence.py` keeps only the encoder's
`ftyp`+`moov` boxes, puts the original small JPEGs in one `mdat` and fixes
`stsz`/`stco`, then patches only the second sample's SOF0 to 64x512. Nothing
else in the JPEG entropy data changes. The result is a container
reconstruction, not a file the upstream encoder writes.

Two inputs: `tiny64-mixed.heif` is 1,195 bytes (SHA-256 `aa8e0600...c58`)
with a 512x64 first frame; `tiny72-mixed.heif` is 1,227 bytes
(`231bb209...e89`) with a genuine 512x72 first frame. On pinned v1.23.6 ASan
the first gives rc 1, `WRITE of size 64`, 0 bytes after a 32,783-byte region;
the second gives rc 1, the same write at `pixelimage.cc:644` via
`heif_image.cc:403` and `encoder_x265.cc:1139`, 0 bytes after a
**36,879-byte region**. Same-size controls rc 0; plain Release rc 139
(64-row first frame) and rc 134 with `double free or corruption (out)`
(72-row first frame); fixed `9ec655f` rc 0 with encode rc 2 and no ASan.
`check_tiny_mjpeg.py` PASS=71 FAIL=0. Hashes, rc files and all eight logs:
`real/neighbour/evidence/tiny-mjpeg/`.

Preserved negatives: 1,195 and 1,227 bytes are 40 and 72 bytes above the
advisory's 1,155, so the exact artifact is still UNTESTED, not matched.
Dropping `ftyp` gives 1,155 bytes but libheif rejects it ("No 'ftyp' box");
short compatible-brand lists either lose sequence detection or fail to decode
the JPEG samples. The 72-row source JPEG logs "Corrupt JPEG data: 11
extraneous bytes before marker 0xd9" although frame 0 decodes 512x72.
Grade UNCHANGED: rung 3 plus rung 4, NOT rung 5; no pointer later used by
x265, command, live consumer or witness verdict. Author observation only.

## W186 structural negative: no decoder path to the padding write (2026-11-24)

Re-inspected the pinned `v1.23.6` source tree at
`lab/frontier/libheif2shell/src/libheif-v1.23.6` to settle whether a
decode-only libheif consumer (for example libvips/imgproxy, which has its own
live loopback lane in this plant) could reach the faulty function. It cannot.
The complete call-site set for `extend_padding_to_size` in `libheif/` is one
public-API wrapper (`api/libheif/heif_image.cc:403`, declared at
`heif_image.h:432`) and six encoder plugins: `encoder_x265.cc:1139`,
`encoder_x264.cc:1022`, `encoder_kvazaar.cc:690`, `encoder_svt.cc:1055`,
`encoder_uvg266.cc:689` and `encoder_vvenc.cc:673`. There is no call site in
any decoder, demuxer or metadata reader. The only remaining reference outside
those sites is a comment at `image/pixelimage.cc:733`.

This explains every W161-W184 reproduction: they all drive the
decoder-to-**encoder** re-encode path, because encoding is the only internal
route into the write. A decode-only consumer cannot trigger it without
explicitly calling the public `heif_image_extend_padding_to_size()` API, which
no image-decoding pipeline does. The pinned builds in this lab compile only
the x265 plugin; the other five encoder call sites are source-present but
unbuilt, so they remain unmeasured alternatives rather than claims.

Negative result, no new reach: no network consumer, no wire byte, no pointer
or command, no witness verdict. Grade UNCHANGED: rung 3 plus rung 4, NOT rung
5; rung 5 UNKNOWN.
