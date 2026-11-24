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

## W6 — allocator neighbour of the negative WRITE (2026-11-23 target mind)

### Builds and probe

- Plain pinned builds of `src/libvips-8.18.2` and `src/libvips-fixed`
  (`meson --buildtype=debug -Db_sanitize=none`, same format flags as the ASan
  builds): `cfg-vuln-plain.log`, `cfg-fixed-plain.log`, both `ninja` rc 0,
  433/433 targets. Only provisioning corrections: the first two `meson setup`
  attempts used a reversed argument order and then `../src/libvips-8.18.2`
  instead of `src/libvips-8.18.2`; neither produced a finding.
- `real/neighbour.c` creates the real memory image with the TIFF-accepted
  geometry, prints the `/proc/self/maps` entries and `mincore()` status around
  `data - 7296`, and calls the same public `vips_region_prepare()` +
  `vips_region_paint(reg, {0,0,4,2}, 0x5a)` as W4. Modes: `layout` (no
  grooming) and `victim` (64 KiB anonymous mapping at `map_start - 65536`,
  placed with `MAP_FIXED_NOREPLACE`, prefilled with `0x11`).

### Observations

- `vips_tracked_malloc()` (pinned `memory.c:304-347`) calls
  `g_try_malloc0(size + 16)` and returns `buf + 16`; on a glibc mmap
  allocation this makes `data = mapping_base + 32`. Therefore the W4
  negative target is `mapping_base - 7264`, not `mapping_base - 7296`.
- Vulnerable `layout`: `MINCORE_TARGET=0 errno=12`, `DELTA=-7264`,
  `bpl=-7296 lskip=18446744073709544320`, `PAINT_ADDR1=data-7296`; no
  `PAINT_DONE` and `RUN_RC=139` (SIGSEGV). `MAP_NEXT_BELOW_HI` is ~2.7e13
  bytes below the crafted mapping, so there is no natural neighbour to hit.
- Vulnerable `victim`: `pre=11` before paint, then `PAINT_DONE` and
  `VICTIM_POST off=58272 byte0=5a byte1=5a before=11 after_end=5a`,
  `RUN_RC=0`. The 160000-byte second memset starts 7264 bytes below the
  crafted mapping, covers the last 7264 bytes of the victim mapping, and
  continues into the valid first line of the crafted image.
- Fixed `layout` and `victim`: `PREPARE=ERR msg=image: dimension overflow`,
  no paint, no `VICTIM_POST`, `RUN_RC=0`.
- `real/run-neighbour.sh` runs 14 anchored check/absent assertions over the
  four runs; `RESULT fail=0` in-tree.

### Negative results and corrections preserved

- The write also overwrites the crafted glibc mmap chunk header at
  `mapping_base`. The first victim run printed `VIPS-WARNING: vips_free: too
  much free` and aborted in `munmap_chunk()` during teardown (rc 134). That
  is an artifact of the deliberate overwrite, not a separate finding; the
  corrected probe finishes with `_exit(0)` after reading the victim bytes
  and returns rc 0.
- A one-pass `/proc/self/maps` scan first printed a bogus
  `GAP_BELOW=124132456128512` because `containing` was still zero when
  earlier mappings were visited. Tracking the previous mapping end fixes it;
  the recorded gap is the distance from the nearest lower mapping.
- No natural control-flow datum at the target, no libvips object deliberately
  placed as the neighbour (the victim is an anonymous mapping), no wire or
  request input, no process-level execution, no marker and no witness verdict
  for this experiment. Rung 4 remains the grade; rung 5 UNKNOWN.

Clean `git archive HEAD` replay at commit `ee9ffd6` (gitignored source and
build trees symlinked in) returned `RESULT fail=0` for both
`run-neighbour.sh` (14 PASS / 0 FAIL) and `run-consumer.sh` (21 PASS /
0 FAIL), both process rc 0. The W6 change is reproducible from the committed
tree, not only the working tree.

## W7 — file-to-consumer stall remains UNKNOWN (2026-11-23 target mind)

Bounded attempt to close the W3 gap: make a crafted TIFF decode finish so a
consumer could run on loader-decoded pixels. No new rung was claimed.

- Loader limits are pinned at `foreign/tiff2vips.c:3122-3128`:
  `samples_per_pixel <= 10000` and `bits_per_sample <= 32`. A 32768x2x16384
  x32-bit TIFF (`real/smallline.tif`) is rejected with
  `tiff2vips: samples out of range` (`real/downstream-small.out`), so ~2.148 GB
  is the smallest line that still overflows `int`. `real/minline.tif`
  (53700x2x10000x32-bit, 154 bytes) gives `DOWNLOAD=OK ...
  sizeof_line=2148000000 sizeof_image=4296000000`, but the consumer still
  printed no `REGION_PREPARE` after 240 s (`real/downstream-min.out`, rc 124).
- `gdb -p` attach failed on this host: `yama/ptrace_scope=1` and
  `ptrace: Inappropriate ioctl for device` (`real/diag-gdb-bt1.txt`,
  `real/diag-gdb-bt2.txt`). `perf` is unusable at
  `perf_event_paranoid=4`. A throwaway SIGPROF/SIGALRM backtrace preload
  sampled `/bin/sleep` correctly but emitted no samples for either consumer;
  it is a tooling negative, not a stack observation.
- Parent-launched gdb (allowed to trace its own child) with breakpoint command
  lists produced `real/gdb-stall-prepare.out` (four nested
  `vips_region_prepare` calls: main → `vips_foreign_load_generate` →
  `vips_image_write_gen` → `vips_sequential_generate` → tilecache),
  `real/gdb-stall-map.out` and `real/gdb-stall-buffer.out`. The last calls
  before the stall are `vips_buffer_unref_ref` → `vips_buffer_new` →
  `vips_region_buffer`, repeated five times; `vips_region_buffer` is entered
  from `vips_tile_new` (`tilecache.c:232`) and `vips_buffer_new()` is entered
  but never returns. `buffer_move()` computes
  `VIPS_IMAGE_SIZEOF_PEL * width * height` (`buffer.c:481-501`), i.e. a
  multi-gigabyte tile buffer for this geometry; the exact instruction at the
  stall was not captured, so allocation is a hypothesis, not an observation.
- Breakpoints at TIFF fill/read entry points (`tiff2vips.c:2520`, `:2384`,
  `:2417`, `:717`, `:719`, set after process start so symbols resolved) were
  never hit within 35 s (`real/gdb-stall-tiff-fill.out`). No scanline read,
  no decoded pixel, no `REGION_PREPARE` return and no negative-offset access
  on loader-decoded pixels was observed.

- Host confounder preserved: at 13:07Z this host had `SwapTotal 8388604 kB`,
  `SwapFree 432 kB` (`/proc/meminfo`), and another mind's unrelated clean
  replay also stalled under that pressure (jq2shell chat, 12:58Z). The W7
  stall is therefore not attributable to the crafted geometry alone; it is
  an UNKNOWN under a memory-constrained host, not a measured loop.

Disposition: the file-to-consumer path remains a negative result. The
acceptance of the crafted header (W2) and the negative-offset write on a
programmatically created real image (W4/W6) are unchanged. No pointer,
control-flow datum, wire input, command, marker or witness verdict. Grade
remains rungs 1-4; rung 5 UNKNOWN.

## W8 — W7 stall mechanism: wake cgroup eager-zero-fill limit (2026-11-23)

W7 left the file-to-consumer stall labeled UNKNOWN under host swap pressure.
One bounded incident measured the mechanism. No rung changed.

- The wake runs in cgroup
  `/user.slice/user-1000.slice/user@1000.service/m2shell.slice/m2shell-plants.slice/m2shell-wake@libvips2shell.service`
  with `memory.max=2147483648` (2 GiB), `memory.high=1610612736` (1.5 GiB)
  and `memory.current` between 4.3e8 and 4.5e8 bytes during the measurement
  (`real/memlimit.out`, `cat /sys/fs/cgroup/.../memory.{max,high,current}`).
  The parent `m2shell-plants.slice` reads `memory.max=10737418240`,
  `memory.high=8589934598`, `memory.current=8133783552` at 15:39Z.
- `real/memlimit.c` is the exact allocation primitive of pinned
  `vips_tracked_aligned_alloc()` (`iofuncs/memory.c:369-414`):
  `posix_memalign(16, N MiB)` followed by an unconditional `memset(buf, 0, N)`.
  `real/run-memlimit.sh` replays only safe sizes: 64 MB in 0.037 s, 256 MB in
  0.401 s, 1024 MB in 1.196 s, all rc 0, 7/7 anchored assertions PASS.
- One-off larger sizes, same probe (`gcc -O0`, `timeout`): 1500 MB produced no
  line in 30 s (rc 124, 15:39:22-15:39:52Z); 2048 MB none in 60 s
  (rc 124, 15:38:01-15:39:03Z); 4300 MB none in 180 s
  (rc 124, 15:34:37-15:37:43Z). A `-O2` build printed a fictitious
  "4300 MB in 0.000 s" because the unused memset was optimized away; do not
  reuse that build.
- Pinned `buffer_move()` (`buffer.c:468-501`) computes
  `new_bsize = sizeof_pel * area.width * area.height` before that call. The
  W7 gdb trace (`real/gdb-stall-buffer.out`) shows five distinct nested
  `vips_buffer_new()` frames in the foreign-load → image-write → sequential →
  tilecache chain. For `minline.tif` the tilecache buffer is one two-row
  tile of ~4.296 GB (`rtiff_read_stripwise` sets
  `vips_sequential(tile_height=2)`, `tiff2vips.c:2949-2985`); a one-row
  variant would still be ~2.148 GB. Both exceed this wake's 2 GiB
  `memory.max`. The stall therefore has a measured host-level cause: eager
  zero-filling above the cgroup high watermark, not a demonstrated libvips
  loop and not evidence of crafted-geometry-specific misbehaviour.

Disposition: file-to-consumer stays a negative result, now with a concrete
mechanism. Host memory limits are a protected guard and were not changed;
no longer timeout can close this path under the current wake cgroup, and a
tiled-TIFF variant was not attempted because its aggregate tile buffers also
scale with the crafted line size ([INFERENCE] from `buffer.c` and
`tiff2vips.c:2614-2666`, not measured). The host swap condition from W7 is
preserved. Grade unchanged: rungs 1-4. No wire, request, command, marker or
witness verdict. Rung 5 UNKNOWN.

Clean `git archive HEAD` replay at commit `d3dc9be` (only the two new probe
files extracted, no build tree needed) returned `CLEAN_ARCHIVE_RC=0` and
`RESULT fail=0` (7/7): 64 MB in 0.069 s, 256 MB in 0.343 s, 1024 MB in
1.190 s, with the same cgroup `memory.max=2147483648`. The in-tree canonical
checks were also rerun after the documentation change: `run-consumer.sh`
21/21 PASS and `run-neighbour.sh` 14/14 PASS, both rc 0; their evidence
outputs were restored to the committed bytes after the run.

## W9 — application-supplied buffer bypasses the W8 zero-fill limit (2026-11-23)

W8's cgroup conclusion covered only libvips-owned allocations. A negative
`int bpl` requires a 64-bit scanline in `(INT_MAX, 2^32)`; the smallest such
line is `2^31 = 2147483648` bytes and a two-line image needs at least twice
that, so no geometry tuning can put a libvips-owned truncatable line under the
2 GiB cap. An application-supplied buffer need not be eagerly zero-filled:

- `real/external.c` reserves an 8.6 GB anonymous `PROT_NONE MAP_NORESERVE`
  mapping, makes only a 64 KiB victim block and 64 pages at the image area
  writable, and passes that pointer to `vips_image_new_from_memory()` with the
  TIFF-accepted geometry (`107374 x 2 x 10000` uint32). No
  `vips_tracked_aligned_alloc()` and no multi-GB `memset` occur.
- Vulnerable plain tree: `IMAGE_OK sizeof_line=4294960000
  sizeof_image=8589920000`, `PAINT_PREPARE=0 bpl=-7296`, `PAINT_ADDR1=data-7296`,
  then `PAINT_DONE` and `VICTIM_POST off=58272 byte0=5a byte1=5a before=11
  after_end=5a`. The chosen ink reaches a mapped neighbour at the chosen
  offset inside the 2 GiB wake cap. Output: `real/external-vuln.out`.
- Fixed plain tree: `IMAGE=ERR msg=image: dimension overflow`, no `PAINT_DONE`,
  no `VICTIM_POST`, victim remains `0x11` (`real/external-fixed.out`).
- First run of the probe segfaulted in `memset` at the first page after the
  victim: `mprotect()` length had been passed as 64 *bytes* instead of 64
  pages. The runner assertions caught it; the fixed length is
  `DATA_PAGES * 4096`. A gdb parent-launch backtrace
  (`vips_region_paint ... region.c:922` → `__memset_avx2_unaligned_erms`)
  located that implementation bug before the correction. No libvips change
  was made in response.
- `real/run-external.sh`: 12/12 anchored assertions PASS, rc 0, in-tree.

Disposition: W8 is narrowed, not overturned. A libvips-owned allocation of a
truncatable line still cannot complete under this cgroup; an application that
supplies a lazily backed image buffer can still reach the same rung-4
negative write. The victim is explicit grooming and holds anonymous bytes —
no pointer, control-flow datum, wire/request input, command or marker side
effect. Grade unchanged: rungs 1-4; rung 5 UNKNOWN.

Clean `git archive HEAD` replay at commit `c8550f8`, with the gitignored
pinned source and plain/ASan build trees symlinked in, returned:
`real/run-external.sh` 12/12 PASS, `RESULT fail=0`; `real/run-consumer.sh`
21/21 PASS, rc 0; `real/run-neighbour.sh` 14/14 PASS, `RESULT fail=0`.
All three process rc 0.

Witness verdict W172 (DM #2882): ESTABLISHED at the labeled W9 scope, no
counterexample, grade unchanged, rung 5 UNKNOWN. Replay in the witness wake
cgroup used a clean `git archive` of `c8550f8`/`3fbe3e6` with gitignored pinned
source and four build trees symlinked in. Built `image.c` hashes matched pins
(`e681b615` vulnerable / `ed6187f6` fixed); the source delta is exactly the
`ls >= INT_MAX` guard at fixed `image.c:693` plus its comment. Fresh runs:
`run-external.sh` 12/12, `run-consumer.sh` 21/21, `run-neighbour.sh` 14/14,
all rc 0. Vulnerable: `IMAGE_OK line=4294960000 bpl=-7296`,
`PAINT_ADDR1=data-7296`, `PAINT_DONE`, `VICTIM_POST byte0=5a byte1=5a`.
Fixed: `image: dimension overflow`, no paint, victim untouched. Counterexample
hunts: changing paint ink to `0x37` moved the victim bytes to `37/37`;
`vipsheader` on `safe.tif` returned rc 0 under both plain libraries, so the
fixed build is not broadly rejecting. Caveat: the replay was in the witness
cgroup, so W8's 2 GiB wake cap was not re-measured; the lazy 8.6 GB reservation
succeeded there. The witness's comment-only NIT — `external.c:7` claiming a
1 MiB image area where `DATA_PAGES * 4096` is 256 KiB — is corrected in this
fold; no probe behavior changed.

## W14 — crafted request bytes over loopback to header acceptance (2026-11-23)

One bounded experiment closing the "no wire/request input" evidence gap at the
header-acceptance scope only. No grade change, no rung-5 claim.

### Materials

- `real/wire.c`: one-shot HTTP/1.0 server, `AF_INET` / `SOCK_STREAM`, bound to
  `INADDR_LOOPBACK` with an **ephemeral port** (`sin_port = 0`), `listen(1)`,
  one `accept()`. Reads at most 1 MiB, finds the `\r\n\r\n` header terminator
  with `memmem`, parses `Content-Length`, then calls
  `vips_image_new_from_buffer(body, len, "", "access",
  VIPS_ACCESS_SEQUENTIAL, NULL)` and prints `WIRE_HDR`, `WIRE_SANITY`, or
  `WIRE_HDR=ERR`. This is the same header-only load as W2 `part_a`
  (`vips_image_new_from_file` with `VIPS_ACCESS_SEQUENTIAL`), fed request bytes
  instead of a filename. No pixel decode, region, paint or command.
- `real/run-wire.sh`: compiles `wire-plain` / `wire-fixed` against the existing
  gitignored `build-vuln-plain` / `build-fixed-plain` trees with the same
  flags as `run-external.sh`, runs four legs (vulnerable/fixed ×
  `manyband.tif`/`safe.tif`), starts the server in the background, waits for
  its printed port, and uses a separate `python3` process to send the POST
  over a real 127.0.0.1 socket. No external address, no fixed port.

### Observations (13/13 anchored assertions PASS, `RESULT fail=0`, rc 0)

- Vulnerable + 154-byte crafted request: `WIRE_REQ body=154
  content_length=154`, `WIRE_HDR Xsize=107374 Ysize=2 Bands=10000 BandFmt=6
  sizeof_line=4294960000`, `WIRE_SANITY=1 msg=`, `RUN_RC=0`
  (`wire-vuln-crafted.out`).
- Fixed + same request: `WIRE_HDR=ERR msg=image: dimension overflow`, no
  `WIRE_HDR Xsize=` line, `RUN_RC=0` (`wire-fixed-crafted.out`).
- Safe 142-byte request under both builds: `WIRE_HDR Xsize=64 Ysize=2
  Bands=4 BandFmt=0 sizeof_line=256`, `WIRE_SANITY=1`, `RUN_RC=0`
  (`wire-vuln-safe.out`, `wire-fixed-safe.out`).
- Ports were ephemeral and differ between legs (39215, 33741, 44731, 36491 in
  the canonical run); assertions match the `WIRE_BIND 127.0.0.1 port=` prefix,
  not a port value.

### Negative results and scope limits

- The hand-written TIFF emits repeated `VIPS-WARNING` lines about Photometric
  channels and `StripByteCounts`; they appear in every leg, including safe,
  and are input-file artifacts. No libvips change in response.
- The crafted request reaches only header acceptance and
  `vips_object_sanity()` on the vulnerable build. It never reaches a TIFF
  scanline read, the truncated `bpl`, `vips_region_*`, a negative-offset
  access or a chosen-byte write. W7/W8's loader-to-pixel stall is unchanged.
- The service is lab scaffolding started by the probe, not a real-world
  network-facing consumer. Per the rung-5 gate this stays UNKNOWN: a live
  consumer must be admitted as its own target, the write must be reached on
  its living bytes, and an independent witness verdict is required.
- Earlier "no wire/request input" statements in sections W6, W7, W8 and W9
  describe those paths; they are not retracted, and W14 adds wire input only
  to this new header-acceptance path.

Grade unchanged: rungs 1-4; rung 5 UNKNOWN. No witness verdict requested for
this scope.

Clean `git archive 520d48f` replay (only `lab/frontier/libvips2shell` and
`reports/frontier-libvips2shell.md`, gitignored source and both plain build
trees symlinked in) returned `RESULT fail=0`, 13/13 PASS, rc 0, same four legs.
The first replay attempt failed at compile because `src` was extracted as a
real directory, so the symlink became `src/src`; removing it before the
symlink fixed the harness setup. This is a replay-procedure error, not a
libvips finding.


## W15 — downstream-consumer claim source pins (2026-11-24)

Read-only provisioning for the standing-#6 claim in report §15. No build,
listener, request or traffic to any non-loopback system. Each digest is
SHA-256 of the exact bytes fetched with `curl -fsSL`.

| Source (tag) | URL | SHA-256 | Observed line |
| --- | --- | --- | --- |
| imgproxy v4.0.0 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.0/docker/Dockerfile` | `ad972a992e5c77f8d7651b1e87bf065f318bf516103a51077344bf3395326b85` | `ARG BASE_IMAGE_VERSION="v4.0.1"` |
| imgproxy v4.0.1 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.1/docker/Dockerfile` | `cb17e8a7ec507ea97b2ddc96d4e9b5a43232665d8aa53da1b97c4f8fad761fd0` | `ARG BASE_IMAGE_VERSION="v4.0.2"` |
| imgproxy v4.0.2 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.2/docker/Dockerfile` | `cb17e8a7ec507ea97b2ddc96d4e9b5a43232665d8aa53da1b97c4f8fad761fd0` | `ARG BASE_IMAGE_VERSION="v4.0.2"` |
| imgproxy v4.0.3 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.3/docker/Dockerfile` | `cb17e8a7ec507ea97b2ddc96d4e9b5a43232665d8aa53da1b97c4f8fad761fd0` | `ARG BASE_IMAGE_VERSION="v4.0.2"` |
| imgproxy v4.0.4 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.4/docker/Dockerfile` | `72d44b8c28d50fd41f7752e2f1cd86c0a6df76ab9fff886191bdbe6b7dbb7496` | `ARG BASE_IMAGE_VERSION="v4.0.3"` |
| imgproxy v4.0.5 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.5/docker/Dockerfile` | `72d44b8c28d50fd41f7752e2f1cd86c0a6df76ab9fff886191bdbe6b7dbb7496` | `ARG BASE_IMAGE_VERSION="v4.0.3"` |
| imgproxy v4.0.6 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.6/docker/Dockerfile` | `cd3e51b8432c0c1f43d3539285890aa89bd9a71ea772d0bedc316b81c0fd0b80` | `ARG BASE_IMAGE_VERSION="v4.0.4"` |
| imgproxy v4.0.7 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.7/docker/Dockerfile` | `cd3e51b8432c0c1f43d3539285890aa89bd9a71ea772d0bedc316b81c0fd0b80` | `ARG BASE_IMAGE_VERSION="v4.0.4"` |
| imgproxy v4.0.15 `docker/Dockerfile` | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.15/docker/Dockerfile` | `ca1f6857cf96c38bf07626b0b1e59a517881f9f0dab380e3c2a5b5086f9d95d1` | `ARG BASE_IMAGE_VERSION="v4.0.8"` |
| docker-base v4.0.0 `versions.sh` | `https://raw.githubusercontent.com/imgproxy/imgproxy-docker-base/v4.0.0/versions.sh` | `5b665cef7f24fdf2445f485404a9e91d10a6e42efea4027bdbc28f816d5026db` | `export VIPS_VERSION=8.18.2` |
| docker-base v4.0.1 `versions.sh` | `https://raw.githubusercontent.com/imgproxy/imgproxy-docker-base/v4.0.1/versions.sh` | `facbda1836acde10a4cb6b7432fea715fd93ac7d2e94a649c9e4ebaaee341754` | `export VIPS_VERSION=8.18.2` |
| docker-base v4.0.2 `versions.sh` | `https://raw.githubusercontent.com/imgproxy/imgproxy-docker-base/v4.0.2/versions.sh` | `8f05da37e948fed50c69a6f1f0aca90def84647e07af22ee575fc32617bcc360` | `export VIPS_VERSION=8.18.2` |
| docker-base v4.0.3 `versions.sh` | `https://raw.githubusercontent.com/imgproxy/imgproxy-docker-base/v4.0.3/versions.sh` | `15c7a29e847c3fdf10304232e776dec25ace775b3fc29005f8ba8cd5d28c085f` | `export VIPS_VERSION=8.18.2` |
| docker-base v4.0.4 `versions.sh` | `https://raw.githubusercontent.com/imgproxy/imgproxy-docker-base/v4.0.4/versions.sh` | `2985b75e18ab98dc0fd9da9ea7914b5cc4afa0bf2fefaae4e9d759d6fee3b454` | `export VIPS_VERSION=8.18.3` |
| docker-base v4.0.8 `versions.sh` | `https://raw.githubusercontent.com/imgproxy/imgproxy-docker-base/v4.0.8/versions.sh` | `8976507ac5c49886f6ed3259dd0214fd5cf779cb55025313aad4dcd48da504c9` | `export VIPS_VERSION=8.18.6` |
| docker-base master `versions.sh` | `https://raw.githubusercontent.com/imgproxy/imgproxy-docker-base/master/versions.sh` | `731ea66bca82bea81075bb4a238370681fdd8af6876312fd64b36e2cca62ff8a` | `export VIPS_VERSION=8.18.7` |

imgproxy's own libvips-loader CVE claim, already in-tree and used only to
evidence the network-facing reachability class, is pinned at
`lab/frontier/imgproxy2shell/PROVENANCE.md` (CVE-2026-123614 /
GHSA-hff9-5pqw-6w9f, imgproxy 4.0.0-<4.0.16). `imgproxy-docker-base` tag
`v3.31.0` returned 404, so the 3.x line's libvips pin is UNVERIFIED.

Negative result preserved: the first candidate, imgproxy v4.0.15, was
**rejected** as a CVE-2026-69242 consumer — its base v4.0.8 pins libvips
8.18.6, above the 8.18.3 fix. The affected range was then found by walking
release Dockerfiles backward to the base-tag boundary (v4.0.3 8.18.2 →
v4.0.4 8.18.3). This is source enumeration, not a runtime measurement: no
imgproxy process was built or run. Grade unchanged: rungs 1–4, rung 5 UNKNOWN.

## W16 — small negative bpl reaches the live vips tracked-size field (2026-11-24)

Routing note from operator #3225: no new target; this CVE stays an adjacent
same-target lane inside libvips2shell under standing #7. The imgproxy live
listener and HTTP request are imgproxy2shell's scope extension. Their W1
(#3250, commits e062321/12056b0) is preserved as the consumer-side negative
result: real imgproxy 4.0.0 accepts the crafted TIFF into `Image.Load` on
8.18.2, default JPEG output dies at `Flatten` (9999/9998 elements), `f:tiff`
enters processing then stalls under the 2 GiB wake cgroup, and the fixed tree
rejects at `Image.Load` with `image: dimension overflow`. No bpl truncation,
region paint, write or marker there. No imgproxy tree was touched by this wake.

### Geometry derivation (from pinned source, then measured)

W14 considered but did not run a scanline tuned close to 2^32. Derivation:
`VIPS_MAX_COORD` default is 100,000,000, so a scanline above 2^31 with width
under the cap needs `ps = Bands * bytes_per_sample >= 43`. Choosing
`Bands=12`, `BandFmt=VIPS_FORMAT_UINT` (4 bytes) gives `ps=48`, and
`89478485 * 48 = 4294967280 = 2^32 - 16`. Casting that 64-bit line size into
the pinned `int VipsRegion.bpl` (`region.c:637`) gives `bpl = -16`.

`vips_tracked_malloc()` stores the allocation size in the 16 bytes before the
returned pointer (`memory.c:312`, `:330-331`); `vips_tracked_free()` reads it
from `data-16..data-9` (`memory.c:220-221`). Pinned
`vips_region_paint_pel()` (`region.c:974-1008`) with `r={0,0,1,2}` computes
`ws = 1 * ps = 48`, `ls = (int) VIPS_REGION_LSKIP = -16`, fills line 0 with
`ink`, then executes `memcpy(to-16, to, 48)` at `:1004`. The first eight
chosen ink bytes (`0x41`) therefore replace the live tracked size.

### Artifacts (SHA-256)

| Artifact | SHA-256 |
| --- | --- |
| `real/fine.c` | `4b3fefc35327a0c70e71d660cfb245b90360440c058e9b91f25768ff6b02c8de` |
| `real/run-fine.sh` | `4e6f5b8a4463812fdb1ba1372beb46e68744a8c48c202b7ae7498568237544a5` |
| `real/fine-vuln-craft.out` | `ef2ff2fa4643e59acf5634d65630bfc4f1dee5ffb5147805adf54632d36df0c0` |
| `real/fine-fixed-craft.out` | `ead0996d8bf1cd5855bb382b903ed553ad8fe240445d2148cd763bba51853eec` |
| `real/fine-vuln-safe.out` | `36848e115e333f1467e387199f60264aa80c0121f16445a7b773524b53c71afd` |
| `real/fine-hdr-vuln.out` | `2ba6794f6012846add7e508b14d7f31386c4859bb798fc9abb7da187c68c1f6a` |
| `real/fine-hdr-fixed.out` | `9059885fe566a815fb9619f5e307a0fe3220f603a5f65391174e7528a8d097da` |

### Observations

Plain pinned builds (not ASan: a redzone would abort at the first poisoned
byte and hide the allocator field). `real/run-fine.sh` builds four probes,
generates `fine.tif` with the committed `mktiff.py`, and runs five legs with a
90 s timeout each; 26 anchored assertions, `RESULT fail=0`, process rc 0,
warning-free compile. The raw `.out` files carry run-specific timestamps and
pointer values; the assertions, not their file digests, are the replayable
evidence.
- Real TIFF header leg: `python3 mktiff.py fine.tif 89478485 2 12 32 3`
  produces a 154-byte file. Vulnerable plain build with `SKIP_CHAIN=1`:
  `TIFF_LOAD=OK filename=fine.tif`,
  `TIFF_HDR Xsize=89478485 Ysize=2 Bands=12 BandFmt=6 sizeof_line=4294967280
  sizeof_image=8589934560`, `TIFF_SANITY=1 msg=`, `CHAIN_SKIPPED=1`,
  `RUN_RC=0`. Fixed plain build: `TIFF_LOAD=ERR msg=image: dimension
  overflow`, `RUN_RC=0`. Header only; no pixel was decoded in this leg.
- Vulnerable + craft: `IMAGE mode=craft Xsize=89478485 Ysize=2 Bands=12
  BandFmt=4 sizeof_line=4294967280 sizeof_image=8589934560`,
  `REGION bpl=-16 lskip=18446744073709551600 valid={0,0,1,2} ws=48`.
  Before: `TRACKED_SIZE_BEFORE=0x1fffffff0`, prefix `-16: f0 ff ff ff 01 00 00 00`.
  After: `PAINT_DONE`, `TRACKED_SIZE_AFTER=0x4141414141414141`, prefix
  `-16: 41 41 41 41 41 41 41 41`, `-8: 5a 5a 5a 5a 5a 5a 5a 5a`,
  `+0: 5a ...`, `+8: 5a ...`. The untouched `-24` glibc chunk bytes are
  `02 10 00 00 02 00 00 00` in both dumps.
- At teardown the corrupted size is consumed:
  `VIPS-WARNING **: vips_free: too much free`,
  `memory: 0 allocations, -4702111225885049169 bytes`, `RUN_RC=0`. No SIGSEGV,
  no `MAP_FIXED_NOREPLACE` victim, no groomed neighbour — unlike W6's
  `bpl=-7296` default layout (`RUN_RC=139`).
- Fixed + craft: `IMAGE=ERR msg=image: dimension overflow`; no region line, no
  `PAINT_DONE`, no `TRACKED_SIZE_AFTER`, no free warning, `RUN_RC=0`.
- Vulnerable + safe (`Xsize=64`, same bands/format): `sizeof_line=3072
  sizeof_image=6144`, `bpl=3072`, `TRACKED_SIZE_BEFORE` and
  `TRACKED_SIZE_AFTER` both `0x1810`, prefix `-16` unchanged, no free warning,
  `RUN_RC=0`.

### Ceiling and preserved limits

This refines W6 from "default layout is unmapped, availability only" to
"a tunable small negative offset reaches a mapped, live allocator accounting
field in the default layout, and chosen bytes there change free-time behaviour".
The field is a `size_t` size used in arithmetic and a warning branch, not a
pointer, vtable, saved return address or control-flow diversion; `0x41` bytes
are not code. The sink is still a direct `vips_region_paint_pel()` call on a
programmatically created memory image: no TIFF pixel decode, no live consumer,
no wire/request in this leg, no command, no marker, no witness verdict. Grade
unchanged: rungs 1–4; rung 5 UNKNOWN. A compile-warning correction during this
wake restored two omitted `printf` arguments; the final build is warning-free.

Clean `git archive 359fc8c` replay (2026-11-24, 03:20Z): extracted
`lab/frontier/libvips2shell` and `reports/frontier-libvips2shell.md` to a fresh
temp directory, symlinked the four gitignored pinned source/plain-build trees
in as at W14, and ran `real/run-fine.sh` from the extracted tree.
`RESULT fail=0`, replay process rc 0, no compiler warnings — same 19/19 as
the working tree. The replay directory `/tmp/libvips-w16-replay.wBWo9S` is a
throwaway and is not committed. This proves the committed harness reproduces
the controls, not that the fixed build broadly rejects images.

Clean `git archive 5f985c5` replay (2026-11-24, 03:22Z): same extraction and
four symlinked gitignored trees as above; `real/run-fine.sh` from the extracted
tree printed 26 `PASS` lines, `RESULT fail=0`, replay process rc 0, no compiler
warnings. The earlier `359fc8c` replay record above was for the 19-assertion
version before the real-TIFF header leg was added; both are preserved. The
replay directory `/tmp/libvips-w16b-replay.2a7lRH` is a throwaway and is not
committed.

Final `git archive HEAD` replay at `d4f24f7` (2026-11-24, 03:24Z), after the
generated probes were gitignored and `fine.tif` was committed: same extraction
and four symlinked trees; 26 `PASS`, `RESULT fail=0`, rc 0, no warnings. The
regenerated `fine.tif` digest `c3e12050213321d5f4f87b4fcac487a0b6588292c92020611bac33f586157d44`
matched the committed fixture. No runner or probe source changed after
`5f985c5`, so this is a final-state confirmation, not a new measurement.

## W17 — consumer HTTP route closed as a preserved negative (2026-11-24)

Unread dossier message #3303 from imgproxy2shell is their W2 consumer-lane
result for W16's fine geometry (their commits `5d5b455`, `4a1977f`; their
`PROVENANCE.md` §W2). This wake recorded it and made no lab change.

- They served this target's committed fixture `real/fine.tif`
  (`c3e12050213321d5f4f87b4fcac487a0b6588292c92020611bac33f586157d44`, §W16)
  through a real imgproxy 4.0.0 process on `127.0.0.1:18080/18081`, `f:tiff`
  output: vulnerable 8.18.2 timed out at 8.09 s (same as the many-band and
  `tiff9999` geometries); fixed 8.18.2+patch returned HTTP 500 in 516 us with
  `image: dimension overflow` at `vips.(*Image).Load`; safe control HTTP 200
  on both. Clean `git archive` replay at `5d5b455` matched at a 6 s timeout.
- No bpl truncation, `vips_region_paint_pel()` frame, allocator-field
  overwrite, pointer, command or marker in the imgproxy process. Their source
  enumeration of pinned v4.0.0 (`vips/vips.go:314-334`, `defs.go:144-156`,
  `scale_on_load.go:29-42`) found no lazy or thumbnail TIFF load path, so
  `bpl=-16` forces the full ~8.59 GB image and the W7/W8 zero-fill stall.
  Host limits untouched; no longer-timeout retry.
- Disposition: preserved negative closing the HTTP consumer route. The
  vulnerable leg is a timeout, not a chosen-byte write; rung 4 is at
  header/entry only. Grade unchanged: rungs 1–4; rung 5 UNKNOWN. The
  library-side primitive and fixed 8.18.3 boundary stay in this lane. This
  wake edited no tree outside `reports/frontier-libvips2shell.md` and this
  provenance file.
