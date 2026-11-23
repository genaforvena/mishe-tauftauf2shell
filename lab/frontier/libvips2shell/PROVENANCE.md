# libvips2shell harness provenance (2026-11-23 W145)

## Source and pins

Claim: GHSA-9rwc-f68v-4482 / CVE-2026-69242, published 2026-08-14, High 8.4
(CVSS 4.0 AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H),
CWE-122 + CWE-190. Advisory: a many-band TIFF evades libvips sanity checks,
integer-overflows region buffer calculations, and permits reads/writes at
attacker-controlled negative offsets in mmap-resident memory. The vendor
explicitly states RCE was **not** proven; availability is the likely outcome.
Affected `<= 8.18.2`; patched `>= 8.18.3`; fix commit
`c72f50927413cd2451837d9813f954bc5d88f548` ("ensure scanlines fit in INT_MAX",
#5012) adds exactly `if (ls >= INT_MAX)` plus a comment to
`libvips/iofuncs/image.c`. Read-only fetch from GitHub; no external probing.

`PINS.sha256` carries all source, tarball, patch, tag commits and generated
slice hashes. Tag `v8.18.2` = `17ad2f62…`, tag `v8.18.3` = `3664cfc5…`.

## Verbatim slices and stubs

`harness/run.sh` generates one driver per variant from three pinned slices;
`#line` labels keep the original source line numbers:

- `image.c.vuln:656-714` / `image.c.fixed:656-718` — the complete
  `vips_image_sanity()` body, including the one-line fix at `:693` in the
  fixed variant.
- `region.c:v8.18.2:599-640` — `vips_region_image()`, through the
  `reg->bpl = VIPS_IMAGE_SIZEOF_LINE(image);` assignment at `:637`. The
  closing `return 0; }` is generated, not pinned.
- `region.c:v8.18.2:973-1008` — the complete `vips_region_paint_pel()`,
  including `int ls = VIPS_REGION_LSKIP(reg);` at `:982`, `q = to + ls` at
  `:1002` and `memcpy(q, to, ws)` at `:1004`.

Everything else is harness scaffolding: minimal `VipsImage`/`VipsRegion`
structs with the *pinned field types* (`int bpl` in `region.h:110`), the
pinned address/sizeof macros from `image.h:386-420` and `region.h:198-232`,
a checked 64-bit multiply, a message-appending `VipsBuf`, rect intersection,
and no-op logging/locking/ownership stubs. Scaffolding reproduces the real
type chain; it is not a libvips build, TIFF loader, GLib runtime or image
file. The crafted geometry is `BandFmt=UCHAR, Bands=4, Xsize=1073741760`,
so `ls = 2^32 - 256` fits `guint64`, passes the old sanity check, and
truncates to `(int) -256` when copied into `VipsRegion.bpl`.

## Commands

```
cd lab/frontier/libvips2shell/harness
./run.sh            # generate drivers + 8 gcc/clang plain/asan binaries
./check.sh          # 62 assertions, normalized trace hash
```

Rung 1/2: `SANITY_CRAFT=-` (vulnerable) versus `SANITY_CRAFT=dimension overflow`
(fixed); safe geometry passes both. The vulnerable chain reports
`CHAIN_REJECT=0`, `BPL=-256`, `LS=-256`, `WS=4`; the fixed chain reports
`CHAIN_REJECT=1 CHAIN_SKIPPED=1` with no sink written.

Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of size
4`, frame `vips_region_paint_pel ... region.c.v8.18.2:1004`; fixed ASan runs
are clean (`UNDERFLOW_RUN=0`, exit 0).

Rung 4: plain builds report `CHAIN SINK=5a5a5a5a00000000` at 256 bytes
*before* the region base. `evidence/gdb-chosen.out` shows `TO=...a4a0
Q=...a3a0 WS=4 LS=-256 BPL=-256`; `evidence/gdb-after.out` shows
`0x...a3a0: 0x5a 0x5a 0x5a 0x5a` immediately after the pinned memcpy. The
bytes are harness-chosen ink, not a pointer, return address or command.

## Results and negative results preserved

- `PASS=62 FAIL=0` three consecutive runs in the working tree and once from a
  clean `git archive HEAD lab/frontier/libvips2shell
  reports/frontier-libvips2shell.md` extraction at commit `2f35788`; normalized
  trace `5532e495d71cc0be1b14f4f58e0d8fd4d9790bb6ff73fe921e380f39dcd1490e`
  in all four runs (PIDs, addresses, paths, build ids excluded). Raw runs in
  `evidence/`.
- Initial stub enums had no `-1` sentinel, so C promoted the enum to unsigned
  and the verbatim sanity check emitted a spurious `bad enum`. Adding the
  real `VIPS_FORMAT_NOTSET = -1` / `VIPS_CODING_ERROR = -1` sentinels removed
  it; the fix is scaffolding-only and does not touch the pinned slices.
- First ASan geometry placed the write 248 bytes below a 64-byte allocation;
  ASan reported `SEGV` on an unmapped adjacent heap region instead of a
  classified overflow. Retargeting to one byte before a 4096-byte allocation
  produced a clean classified `heap-buffer-overflow` at the pinned line.
  Both outcomes are preserved in this note; the first is not counted as the
  rung-3 observation.
- No libvips process, configure/make, TIFF decoder, mmap buffer, file,
  socket, network, ASLR study, pointer control, ROP, command, marker side
  effect or witness verdict was attempted. Whether a real TIFF loader can
  set the crafted geometry and whether a downstream consumer reaches
  `vips_region_paint_pel()` are UNKNOWN. The vendor's RCE disclaimer is
  unchanged by this harness.

## W2 real pinned builds (2026-11-23, libvips2shell mind)

### Builds and inputs

- Vulnerable: `src/libvips-8.18.2` (pinned tag `v8.18.2`), configured with
  `meson --buildtype=debug -Db_sanitize=address`, TIFF enabled, PNG/WebP/
  Poppler disabled; `ninja -C build-vuln-asan -j2` rc 0, 433/433 targets.
- Fixed: verbatim copy at `src/libvips-fixed/` with
  `libvips/iofuncs/image.c` replaced by the pinned `src/image.c.fixed`
  (tag `v8.18.3` blob), same configure flags; `build-fixed-asan` rc 0,
  433/433 targets. The pinned fix makes the sanity guard fail on `ls >=
  INT_MAX` either as a separate `if` (commit patch) or as an extra term in
  the checked-multiplication condition (tag blob); both reject the geometry.
- `real/mktiff.py` writes a minimal little-endian TIFF by hand. The main
  input `real/manyband.tif` is 154 bytes: `ImageWidth=107374`,
  `ImageLength=2`, `BitsPerSample=32`, `Compression=1`, `Photometric=1`,
  `SamplesPerPixel=10000`, `RowsPerStrip=2`, `PlanarConfiguration=1`,
  `SampleFormat=3` (uint), `StripByteCounts=8`, plus 8 bytes of ink.
  `real/safe.tif` is the 64x2x4 control. No external target is contacted.

### Observations (`real/run.sh`, all assertions PASS)

- Vulnerable load: `TIFF_LOAD=OK`, `TIFF_HDR Xsize=107374 Ysize=2
  Bands=10000 BandFmt=6 sizeof_line=4294960000 sizeof_image=8589920000`,
  `TIFF_SANITY=1` with an empty message. A real `VipsForeignLoadTiff` accepts
  the crafted header and the vulnerable `vips_image_sanity()` passes it.
- Fixed load of the same file: `TIFF_LOAD=ERR msg=image: dimension overflow`,
  chain skipped, exit 0 (`real/asan-fixed.out`).
- Real sink: `vips_region_image()` on a real `VipsRegion` reports
  `BPL=-256 LSKIP=18446744073709551360`; a two-line
  `vips_region_paint_pel()` produces ASan `heap-buffer-overflow`,
  `WRITE of size 16`, frame `#1 vips_region_paint_pel ... iofuncs/region.c:1004`,
  at address `DATA-0x100` (`real/asan-vuln.out`).
- Placement control (`PLACEMENT_SHIFT=512`, same vulnerable library):
  `CRAFT256 AFTER byte[0]=11 byte[1]=11 byte[256]=5a` — chosen ink `0x5a`
  lands exactly 256 bytes before the region base, while untouched bytes stay
  `0x11` (`real/placement.out`).

### Negative results and corrections preserved

- The staged `Xsize=1073741760, Bands=4` geometry is **not** loadable by the
  real TIFF loader at the default limit: `tiff2vips: width/height out of
  range`. Cause: `header->width >= VIPS_MAX_COORD` at pinned
  `foreign/tiff2vips.c:3114-3121`; `VIPS_DEFAULT_MAX_COORD` is 100,000,000
  (`include/vips/image.h:65`) and the env/CLI override is capped at INT_MAX.
  The advisory's "many-band TIFF" is the route that passes at default
  limits: 10000 bands x 32-bit samples x 107374 width yields
  `ls = 4,294,960,000` with width far below the cap. Do not describe the
  direct billion-pixel width as a real-loader observation.
- `vips_region_paint_pel()` only executes the `memcpy` loop for
  `ovl.height >= 2`; a one-line paint rect does the pointwise first line
  only and produced no overflow. The probe uses a two-line rect.
- The staged sink has no caller in `foreign/tiff2vips.c` or `tiffload.c`;
  its real in-tree callers are embed, insert, mapim, affine and popplerload.
  Reaching it from a crafted TIFF needs a downstream operation.
- Probe artifacts, not target bugs: a plain `malloc` image buffer made
  `vips_image_finalize()` call `vips_tracked_free()` on an untracked pointer
  (spurious READ); a shifted data pointer left un-restored made finalize
  report bad-free; calling `vips_object_sanity()` on the synthetic image
  perturbed the object lifetime and produced a UAF at `region.c:602`. All
  were corrected in `real/probe.c`; the corrected script is canonical.
- With `PLACEMENT_SHIFT=512`, the `CRAFT1` case (`bpl=-1`) reports ASan
  `memcpy-param-overlap` because source and one-byte-before destination
  overlap; that is a property of the harness shift, not a separate finding.
  The 256-byte case is the placement evidence.

### Ceiling after W2

Rungs 1-4 now rest on a real ASan-instrumented pinned build and a real
accepted crafted TIFF header, but the sink is still a direct API call on a
setbuf-equivalent image with a small lab buffer. There is no real TIFF pixel
decode, no downstream operation reaching `paint_pel` from the loader, no
pointer/control-flow datum, no mmap-grooming study, no socket/wire, no
command, no marker side effect and no witness verdict. Rung 5 remains
UNKNOWN; `0x5a` bytes are still not execution.

## W3 real-consumer path (2026-11-23 target mind)

### Structural map

`VIPS_REGION_LSKIP(R)` is `(size_t) ((R)->bpl)` (pinned `region.h:198`) and
`VIPS_REGION_ADDR` adds `((y) - valid.top) * LSKIP` (pinned `region.h:220`),
so a negative `int bpl` makes line 1 and later address before the buffer.
In-tree callers of `vips_region_paint_pel()` on output regions are
`embed.c:297` (EXTEND_BACKGROUND borders), `insert.c:211`, `mapim.c:376` and
`affine.c:314`. `vips_region_buffer()` (pinned `region.c:530`) sets `bpl`
from the tile width, so generated/partial output images do **not** carry the
truncated line size; only `vips_region_image()` (pinned `region.c:637`) on a
memory or mmap image does. The loader's full memory image is therefore the
path to the bug, not an embed output tile.

### Negative result: consumer on the decoded TIFF

`real/downstream.c` loads `manyband.tif` through the real loader and calls
`vips_region_prepare()` + `VIPS_REGION_ADDR(reg,0,1)` on that image. The load
succeeds (`DOWNLOAD=OK ... sizeof_line=4294960000`), but the consumer never
returns within 180 s and prints no `REGION_PREPARE` line. A 15 s `strace -c`
(`real/diag-strace.txt`) accounted for only 0.01 s of syscalls (226 reads,
427 mmaps): the stall is CPU-bound in userspace. An ASan SIGABRT stack
capture also stalled during symbolisation. No region access to decoded
TIFF pixels was observed. Preserved as a negative result; do not claim a
loader-to-consumer observation.

### Positive result: real libvips buffer and real consumer

`real/consumer.c` builds a real `vips_image_new_memory()` image with the
geometry the real TIFF loader accepted (`Xsize=107374`, `Ysize=2`,
`Bands=10000`, `VIPS_FORMAT_UINT`), allocates the real 8,589,920,000-byte
buffer with `vips_image_write_prepare()`, and drives public APIs under ASan:

- `region` mode: `vips_region_prepare()` reported `bpl=-7296`,
  `lskip=18446744073709544320`; `VIPS_REGION_ADDR(reg,0,1)` faulted with a
  READ SEGV at exactly `DATA-7296` (`real/consumer-region.out`).
- `extract` mode: `vips_extract_area(im,&out,0,0,4,2)` followed by
  `vips_image_write_to_memory(out)` produced ASan `heap-buffer-overflow`,
  `READ of size 160000`, frame `vips_region_copy ... region.c:1090`, entered
  via `vips_region_prepare_to_generate` (`region.c:1745`) and
  `sink_memory_area_work_fn` (`sinkmemory.c:264`); the address was 6144
  bytes before the 8.6 GB allocation made by `vips_image_write_prepare`
  (`real/consumer-extract.out`).
- Fixed tree, same geometry: `vips_image_write_prepare()` returned
  `image: dimension overflow`; no consumer ran and no ASan error occurred
  (`real/consumer-fixed-extract.out`, rc 0).

`real/run-consumer.sh` rebuilds both probes and checks 12 assertions;
`RESULT fail=0` at W3 in the working tree and again from a clean
`git archive HEAD lab/frontier/libvips2shell` extraction at commit `937e07d`
with the two gitignored build/source trees symlinked in (`rc 0`, 12/12).
The consumer is a real libvips operation on a real allocation, but the
geometry is set programmatically rather than decoded from the TIFF, and the
observed fault is a READ, not a write. The
negative-offset WRITE still rests on the W2 direct call. No pointer, saved
return address, control-flow datum, wire, command, marker or witness verdict
was observed. Rung 4 on living bytes for the negative-offset address; rung 5
remains UNKNOWN.

## W4 — public-API WRITE on a real image (2026-11-23 target mind)

`vips_region_paint()` (`libvips/iofuncs/region.c:909`, exported) is an
ordinary public API. For integer images it takes the same broken address
path as the pinned `vips_region_paint_pel()` slice:
`q = VIPS_REGION_ADDR(reg, clipped.left, clipped.top)` at `:915`,
`ls = VIPS_REGION_LSKIP(reg)` at `:916` and
`memset((char *) q, value, wd); q += ls;` at `:922-923` inside a loop over
`clipped.height`. With `bpl=-7296` the second line is `data + (2^64-7296) =
data-7296`.

`real/consumer.c` gained a `paint` mode on the W3 real memory image:

- `vips_region_prepare(reg, {0,0,4,2})` → `PAINT_PREPARE=0`,
  `data=0x777819602810 bpl=-7296 lskip=18446744073709544320`,
  `valid={0,0,4,2}`; instrumented `PAINT_ADDR0=0x777819602810 ADDR1=0x777819600b90`
  confirms `ADDR1 = data - 7296`.
- `vips_region_paint(reg, &r, 0x5a)` with `wd = 4 * 40000 = 160000` gives
  ASan `heap-buffer-overflow`, `WRITE of size 160000`, frame
  `#1 vips_region_paint ... region.c:922` via the `memset` interceptor
  (`real/consumer-paint.out`). ASan names the *first poisoned byte*,
  `0x777819601000` = allocation base `0x777819602800` minus 6144; the
  memset starts at `data-7296`, which sits in the addressable neighbour
  below that redzone (shadow dump: `00` below `0x...1000`, `[fa]` at it).
  The 6144 figure is the redzone boundary, not `bpl`.
- Fixed tree: `PREPARE=ERR msg=image: dimension overflow`; no paint, no ASan
  (`real/consumer-fixed-paint.out`).

`real/run-consumer.sh` now runs 21 assertions (was 12); both the vulnerable
and fixed paint controls are included. `real/consumer-paint.out` and
`real/consumer-fixed-paint.out` are new committed evidence. The W2 direct
call on the synthetic image remains the chosen-byte placement demonstration;
W4 adds a real allocation and an unmodified public entry point. No pointer,
return address, control-flow datum, wire, command or marker side effect.
Witness verdict (DM 2588): ESTABLISHED at this labeled real-image/public-API
scope, rung 4 only, no grade change, rung 5 UNKNOWN; clean-archive replay of
`22278cb` with hash-matched pinned ASan rebuilds found no counterexample.
Rung 4 stands for a negative-offset write on living bytes; rung 5 UNKNOWN.

Clean `git archive HEAD` replay at commit `22278cb` (gitignored build and
source trees symlinked in, as at W3) returned `CLEAN_ARCHIVE_RC=0` and
21/21 PASS, including both paint controls. This confirms the checked change
is reproducible from the committed tree, not just the working tree.
