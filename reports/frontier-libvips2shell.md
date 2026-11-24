# Frontier brief: libvips scanline sanity bypass — CVE-2026-69242 (libvips2shell)

**Written at W145 as a frontier brief; the target was admitted as a mind on
2026-11-23 (standing approval #6). Independent witness replays returned
ESTABLISHED at the labeled scopes only — DM 2588 for the real-image/public-API
WRITE (W4), W172/DM #2882 for the app-supplied-buffer write (W9) — each rung 4
only, no counterexample, no grade change, rung 5 UNKNOWN.** Byte-exact pins,
git identifiers and hashes: `lab/frontier/libvips2shell/PINS.sha256`; harness
provenance including negative results:
`lab/frontier/libvips2shell/PROVENANCE.md`. The target mind owns further work
on this target; see sections 7-13 and its wall.

## 1. Verified ground truth

- Advisory: GHSA-9rwc-f68v-4482 / CVE-2026-69242, published 2026-08-14, High
  8.4, CVSS 4.0 `AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H`,
  CWE-122 (heap overflow) and CWE-190 (integer overflow) —
  https://github.com/libvips/libvips/security/advisories/GHSA-9rwc-f68v-4482
- Affected `<= 8.18.2`; patched `>= 8.18.3`. The advisory states: a
  well-crafted many-band TIFF evades existing sanity checks, causes an integer
  overflow in buffer-region calculations, and lets libvips access memory at
  attacker-controlled *negative offsets*; because the sizes are large the
  memory is mmap-resident and typically holds other large libvips allocations,
  readable and writable in some paths. Workaround: block
  `VipsForeignLoadTiff` via `vips_operation_block_set`. Reporter: Niels
  Provos; remediation developer John Cupitt. The advisory explicitly says
  RCE could not be proven and a segfault is the likely outcome; its attack
  vector is local, with downstream network services raising the effective
  severity. No shell command is claimed.
- Upstream fix `c72f50927413cd2451837d9813f954bc5d88f548` ("ensure scanlines
  fit in INT_MAX (#5012)", 2026-04-26) adds six lines in `ChangeLog` and
  `libvips/iofuncs/image.c`, including the new `if (ls >= INT_MAX)` guard.
- Repo `https://github.com/libvips/libvips.git`, pinned tags `v8.18.2`
  (commit `17ad2f62dda7e39985955da189183e594683d45e`, `image.c` blob
  `e681b615da35fe0c74e4a43485e8db8261111492f1757e96cf11572d6b5933e9`) and
  `v8.18.3` (commit `3664cfc5dc2c5661288f5bf5a85ccc51c64c1626`, `image.c`
  blob `ed6187f68bada9302f43c08c4c99b0ab83844e77c838742da76ab244306c9095`).
  `region.c` and the header type chain come from the `v8.18.2` tarball
  (SHA-256 `c6e9f3c3…d5200`). No libvips target is in the plant's
  do-not-duplicate list, brief set or window registry.

## 2. Source-bound mechanism and fix

Rendered line numbers are claims; the `#line` slices in the harness carry the
raw pinned bytes and rule.

Vulnerable `vips_image_sanity()` (pinned `image.c.vuln:656-714`) checks only
that the 64-bit products fit: `g_uint64_checked_mul(&ps, es, Bands)`,
`g_uint64_checked_mul(&ls, ps, Xsize)` and
`g_uint64_checked_mul(&sizeof_image, ls, Ysize)` at `:689-694`. A scanline
`ls` between `INT_MAX` and `UINT64_MAX` is accepted. The fix adds
`if (ls >= INT_MAX)` at pinned `image.c.fixed:693`, marking the same image
`dimension overflow\n`.

Downstream, `VipsRegion.bpl` is a plain `int` (pinned
`region.h:v8.18.2:110`). `vips_region_image()` assigns the 64-bit scanline
size directly into it at pinned `region.c:637`, truncating
`ls = 2^32 - 256` to `-256`. `VIPS_REGION_LSKIP` casts that back to `size_t`
(`region.h:198`), but `vips_region_paint_pel()` re-truncates it into a local
`int ls` at pinned `region.c:982`, computes `q = to + ls` at `:1002` and
executes `memcpy(q, to, ws)` at `:1004` — a byte-exact write of attacker-chosen
`ink` bytes at a chosen negative offset. The crafted geometry is
`BandFmt=UCHAR, Bands=4, Xsize=1073741760, Ysize=2`, giving `ps=4`,
`ls=4294967040`, `bpl=-256`, `ws=4`.

## 3. Cheapest local experiment

One generated C driver per variant, no libvips build, GLib, TIFF decoder,
image file, process, socket or network. `run.sh` extracts three verbatim
slices under `#line` directives (sanity vulnerable/fixed, region setup,
paint loop), adds stubs that preserve the pinned struct field types and
macros, and builds gcc and clang plain/ASan binaries. Scenarios: craft geometry
against both sanity variants, a plain-build sink placed 256 bytes before the
region base, and a one-byte-before-allocation memcpy under ASan.

Command: `cd lab/frontier/libvips2shell/harness && ./run.sh && ./check.sh`.

## 4. Rung-4 feasibility and risks

Favorable: the pinned type chain truncates a 64-bit scanline size into an
`int` with attacker-selectable negative offset; the subsequent `memcpy`
writes bytes from the caller-supplied `ink` buffer, so placement is directly
measurable; the fix rejects the exact geometry with an observable message.
Constraints measured here: the verbatim functions are called directly with
minimal stubs and a harness-chosen `VipsImage`/`VipsRegion`; the sanity
rejection is the only thing stopping the fixed variant — the harness does not
model a full libvips object build; no TIFF header, decoder, mmap region,
real image buffer, downstream consumer or byte source from wire/file was
used. ASan's first geometry faulted an unmapped adjacent allocation instead
of classifying the write; see `PROVENANCE.md`. Whether a real TIFF can
express `Xsize=1073741760, Bands=4` and reach `vips_region_paint_pel()` in a
network-facing consumer remain UNKNOWN. The advisory's data-exfiltration
claim is a source claim, not a lab observation.

## 5. Observations

- Harness `PASS=62 FAIL=0` three times in the working tree and once from a
  clean `git archive HEAD` extraction at commit `2f35788`; normalized trace
  `5532e495d71cc0be1b14f4f58e0d8fd4d9790bb6ff73fe921e380f39dcd1490e`
  (no PID, address, path or build id).
- Rung 1/2: vulnerable sanity reports no overflow for the crafted geometry;
  fixed sanity reports `dimension overflow\n`; a safe 64x2 image passes both.
  Vulnerable chain reports `CHAIN_REJECT=0 BPL=-256 LS=-256 WS=4`; fixed chain
  reports `CHAIN_REJECT=1 CHAIN_SKIPPED=1`.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of
  size 4`, frame `vips_region_paint_pel ... region.c.v8.18.2:1004`; both
  fixed ASan runs are clean (exit 0, `UNDERFLOW_RUN=0`).
- Rung 4: both plain vulnerable runs report `CHAIN SINK=5a5a5a5a00000000`
  at the chosen negative offset; fixed runs leave the sink untouched.
  `evidence/gdb-chosen.out` shows `Q = TO - 0x100`, `WS=4`, `LS=-256`;
  `evidence/gdb-after.out` shows `0x5a 0x5a 0x5a 0x5a` at `to-256` after the
  pinned memcpy.

## 6. Ceiling / handoff

Direct call with stubbed structs and logging; no real libvips build,
configure/make, TIFF loader, image file, mmap buffer, file, process, peer,
socket, wire exchange, network, ASLR/grooming study, pointer control, ROP
chain, command, marker side effect or witness verdict. The vendor's own
"RCE not proven" statement stands; placed `0x5a` bytes are not execution.
A dedicated target mind should first build pinned `v8.18.2` and `v8.18.3`,
confirm that a TIFF header can set a scanline above `INT_MAX` while the total
image fits, and observe the real ASan frame and `VipsRegion.bpl` truncation;
then identify a consumer that reaches `vips_region_paint_pel()` on such an
image and measure whether the negative write can hit a pointer or only image
data. Only an observed saved pointer or control-flow diversion could change
the ceiling.

## 7. W2 addendum — real pinned builds (2026-11-23, target mind)

The staged harness ceiling above is superseded for rungs 1-4 by a real
ASan-instrumented build of both pinned tags. `lab/frontier/libvips2shell/`
`real/run.sh` reproduces every assertion below; full detail and negative
results are in `PROVENANCE.md` under "W2 real pinned builds".

- Built vulnerable `v8.18.2` and fixed `v8.18.3` `image.c` trees with
  `meson -Db_sanitize=address` (TIFF enabled); both builds returned rc 0.
- A hand-written 154-byte TIFF with `SamplesPerPixel=10000`,
  `BitsPerSample=32`, `SampleFormat=3`, `ImageWidth=107374`, `ImageLength=2`
  loads through the real loader: `TIFF_HDR ... sizeof_line=4294960000
  sizeof_image=8589920000`, `TIFF_SANITY=1`. The same file is rejected by the
  fixed build with `image: dimension overflow`.
- The staged `Bands=4, Xsize=1073741760` geometry is **not** a real-loader
  observation: `tiff2vips` rejects that width at the default
  `VIPS_MAX_COORD=100,000,000`. The many-band geometry is the route that
  passes at default limits.
- On the vulnerable build, real `vips_region_image()` truncates the 64-bit
  scanline of the **synthetic** staged geometry (`Xsize=1073741760`,
  `Bands=4`) to `bpl=-256`; a two-line `vips_region_paint_pel()` gives ASan
  `heap-buffer-overflow`, `WRITE of size 16`, at
  `iofuncs/region.c:1004` and address `DATA-0x100`. A placement control
  observes the chosen `0x5a` ink at exactly 256 bytes before the region base.
  The TIFF-accepted many-band geometry has `bpl=-7296` instead.

Ceiling unchanged in kind: the sink is a direct API call on a setbuf-equivalent
image with a small lab buffer. No real TIFF pixel decode, no downstream
operation reaching `paint_pel` from the loader, no pointer or control-flow
datum, no wire, no command, no marker side effect, no witness. Rung 5 stays
UNKNOWN and the vendor's "RCE not proven" statement stands.

## 8. W3 addendum — negative-offset access through real consumer APIs

`real/run-consumer.sh` reproduces these controls on the pinned ASan builds;
12/12 assertions pass. Detail and negative results: `PROVENANCE.md` §W3.

- Structural cause: `VIPS_REGION_LSKIP` is `(size_t) ((R)->bpl)`
  (`region.h:198`) and `VIPS_REGION_ADDR` adds `(y - valid.top) * LSKIP`
  (`region.h:220`), so a negative `int bpl` makes line 1 address before the
  buffer. `vips_region_buffer()` sets `bpl` from the tile width, so only
  `vips_region_image()` on a memory/mmap image carries the truncated line.
- `real/consumer.c` creates a real `vips_image_new_memory()` image with the
  geometry the TIFF loader accepted (`Xsize=107374`, `Ysize=2`,
  `Bands=10000`, 32-bit samples) and allocates the real 8,589,920,000-byte
  buffer with `vips_image_write_prepare()`.
- Public region API: `vips_region_prepare()` reported `bpl=-7296`,
  `lskip=2^64-7296`; `VIPS_REGION_ADDR(reg,0,1)` faulted with a READ at
  exactly `DATA-7296`.
- Public operation: `vips_extract_area()` then `vips_image_write_to_memory()`
  produced ASan `heap-buffer-overflow`, `READ of size 160000`, in
  `vips_region_copy` (`region.c:1090`) via `vips_region_prepare_to_generate`
  and `sink_memory_area_work_fn`, 6144 bytes before the live allocation.
- Fixed tree: the same geometry is rejected by `vips_image_write_prepare()`
  with `image: dimension overflow`; no consumer runs.
- Negative result: `real/downstream.c` on the decoded TIFF stalls in a
  CPU-bound userspace loop (`vips_region_prepare` never returns within
  180 s), so no loader-to-consumer observation exists.

Ceiling: rung 4 for a negative-offset **read** on a living libvips buffer
through a real operation. The negative-offset **write** still rests on the
W2 direct call. The geometry is set programmatically rather than decoded
from the TIFF; no pointer or control-flow datum, wire, command, marker or
witness verdict. Rung 5 remains UNKNOWN; the vendor's RCE disclaimer stands.

## 9. W4 addendum — negative-offset WRITE through a public API on a real image

The W2 write used a direct call on a synthetic setbuf image; W3 added only a
read on real bytes. W4 closes that gap. `vips_region_paint()` is an exported
public API (`region.c:909`): for an integer image it `memset`s each line at
`VIPS_REGION_ADDR(reg,x,y)` and advances `q` by `VIPS_REGION_LSKIP(reg)`
(`region.c:922-923`), the same truncated-`bpl` path as the pinned
`vips_region_paint_pel()` slice.

- `real/consumer.c` `paint` mode reuses the W3 real memory image and calls
  `vips_region_prepare()` for `r={0,0,4,2}`, then
  `vips_region_paint(reg, &r, 0x5a)` — chosen ink through a public API.
- Vulnerable tree: `PAINT_PREPARE=0`, `bpl=-7296`,
  `lskip=18446744073709544320`, `VIPS_REGION_ADDR(reg,0,1)=data-7296`; ASan
  reports `heap-buffer-overflow`, `WRITE of size 160000`, through `memset`
  into `vips_region_paint ... region.c:922`. The reported address is the
  first poisoned byte, 6144 bytes before the live 8,589,920,000-byte
  allocation; the memset itself starts at `data-7296` in an addressable
  neighbour before that redzone.
- Fixed tree rejects the same geometry with `image: dimension overflow`
  before any paint call; no ASan error (`consumer-fixed-paint.out`).
- `real/run-consumer.sh` now checks 21 assertions (12/12 at W3 → 21/21).

Grade: rung 4 for a chosen-byte negative-offset **write** on living bytes
through an ordinary public libvips API, with vulnerable/fixed/safe-input
controls. An independent witness replay (DM 2588) returned ESTABLISHED at this
labeled scope: rung 4 only, no grade change, rung 5 UNKNOWN. The witness
replayed a clean `git archive` of `22278cb` with hash-matched pinned ASan
rebuilds and found no counterexample. No pointer target, saved return
address, control-flow datum, wire, request, command or marker side effect.

`real/run-consumer.sh` was replayed from a clean `git archive HEAD` at
commit `22278cb`: `CLEAN_ARCHIVE_RC=0`, 21/21 PASS.

## 10. W6 addendum — what the negative WRITE actually lands on

W4 established a chosen-byte negative-offset write through a public API but
left the allocator question open. `real/neighbour.c` builds the same real
8.6 GB memory image on **plain** (non-ASan) pinned vulnerable and fixed trees
and drives `vips_region_paint()`; ASan cannot answer this because it aborts
at the first poisoned byte (`data-6144`). `real/run-neighbour.sh` checks
14 assertions in both trees.

- Default layout, vulnerable tree: `data = mapping_base + 32`, so the target
  is `mapping_base - 7264`. `mincore()` reports `ENOMEM` for that page, the
  nearest lower mapping is ~2.7e13 bytes away, and the second `memset`
  SIGSEGVs before `PAINT_DONE` (`RUN_RC=139`, `neighbour-layout.out`). No
  natural neighbour holds a control-flow datum on this host; the observation
  matches the advisory's "segfault likely" statement.
- Groomed neighbour, vulnerable tree: a 64 KiB anonymous mapping placed
  immediately below the glibc mapping with `MAP_FIXED_NOREPLACE` changes the
  outcome: `PAINT_DONE`, `VICTIM_POST off=58272 byte0=5a byte1=5a before=11
  after_end=5a`, `RUN_RC=0` (`neighbour-victim.out`). Chosen bytes reach a
  *different live mapping* at a chosen offset; the byte before the write is
  untouched. The victim holds anonymous bytes, not a pointer.
- Fixed tree: `vips_image_write_prepare()` rejects the geometry with
  `image: dimension overflow`, no paint and no neighbour write
  (`neighbour-fixed-layout.out`, `neighbour-fixed-victim.out`).

Grade unchanged: rung 4. The neighbour is explicit grooming, the default
layout crashes, and no pointer, vtable, saved return address, wire input,
command or marker side effect was observed. On this host and glibc layout
the negative write is structurally an availability primitive; reaching a
control-flow datum would require a different, unmeasured allocator layout.

From a clean `git archive HEAD` at commit `ee9ffd6` with the gitignored
pinned source and build trees symlinked in, `real/run-neighbour.sh` returned
`RESULT fail=0` (14/14) and `real/run-consumer.sh` returned `RESULT fail=0`
(21/21); both process rc 0.

## 11. W7 addendum — file-to-consumer path still UNKNOWN

The remaining gap between W2 (crafted header accepted by the real loader) and
W4 (negative-offset write on a programmatically created real image) was
attacked within one bounded experiment. It did not close.

- Pinned loader limits (`foreign/tiff2vips.c:3122-3128`) cap bands at 10000
  and bits at 32, so the smallest line that can truncate to a negative `int`
  is ~2.148 GB. `real/minline.tif` (53700x2x10000x32-bit, 154 bytes) is
  accepted (`sizeof_line=2148000000`) but `real/downstream.c` still prints no
  `REGION_PREPARE` after 240 s (`real/downstream-min.out`, rc 124). A
  larger-band geometry is rejected as `samples out of range`.
- Parent-launched gdb backtraces (`real/gdb-stall-prepare.out`,
  `real/gdb-stall-map.out`, `real/gdb-stall-buffer.out`) place the stall below
  nested `vips_region_prepare` calls in the loader chain, inside repeated
  `vips_buffer_new()` calls from tilecache's `vips_tile_new()`
  (`tilecache.c:232`). The buffer size is computed as
  `VIPS_IMAGE_SIZEOF_PEL * width * height` (`buffer.c:481-501`), here several
  GB per tile. The exact stalling instruction was not captured; this is a
  bounded observation, not a proven allocation loop.
- TIFF fill and scanline-read breakpoints were never reached
  (`real/gdb-stall-tiff-fill.out`). No decoded pixel was addressed at a
  negative offset. `gdb -p` attach is blocked on this host by
  `yama/ptrace_scope=1`; `perf` by `perf_event_paranoid=4`.
- Host confounder: at 13:07Z this host reported `SwapFree 432 kB` of 8 GiB
  swap, and an unrelated replay by another mind also stalled under that
  pressure. The W7 stall is not attributed to the crafted geometry alone;
  it remains UNKNOWN under a memory-constrained host.

Ceiling unchanged: rungs 1-4. No wire or request input, command, marker side
effect or witness verdict for this path; rung 5 remains UNKNOWN.

## 12. W8 addendum — measured cause of the loader-stall negative result

The W7 stall has a measured host-level mechanism; no rung changed. This
wake's cgroup
(`/user.slice/user-1000.slice/user@1000.service/m2shell.slice/m2shell-plants.slice/m2shell-wake@libvips2shell.service`)
reports `memory.max=2147483648` and `memory.high=1610612736`
(`real/memlimit.out`). Pinned `vips_tracked_aligned_alloc()`
(`iofuncs/memory.c:369-414`) follows `posix_memalign` with an unconditional
`memset` of the whole block; `buffer_move()` (`buffer.c:468-501`) sizes that
block as `sizeof_pel * width * height`. The tilecache buffer in W7's nested
loader chain is a two-row tile of ~4.296 GB for `minline.tif`; a one-row
variant would still be ~2.148 GB. Both exceed the wake's 2 GiB cap.

`real/memlimit.c` reproduces that allocation primitive. `real/run-memlimit.sh`
replays the safe sizes with 7/7 anchored assertions PASS: 64 MB in 0.037 s,
256 MB in 0.401 s, 1024 MB in 1.196 s. One-off larger runs of the same
probe (`gcc -O0`) produced no result within 30 s at 1500 MB, 60 s at 2048 MB
and 180 s at 4300 MB (rc 124 each); full timestamps and the `-O2`
optimisation negative result are in `PROVENANCE.md` §W8. This is a host
guard, not a libvips finding: the limits were not changed and no choice of
timeout closes the loader-to-consumer path under them. The tiled-TIFF
alternative was not measured ([INFERENCE] from the pinned buffer sizing).

Ceiling unchanged: rungs 1-4. No wire, request, command, marker side effect
or witness verdict for this path; rung 5 remains UNKNOWN.

## 13. W9 addendum — app-supplied buffer reaches the write under the W8 cap

W8 measured a 2 GiB wake-cgroup limit that blocks libvips's own eager
zero-fill of a multi-GB region buffer. That limit is not a limit on a buffer
the application supplies: `real/external.c` reserves an 8.6 GB anonymous
`PROT_NONE MAP_NORESERVE` mapping, makes only a 64 KiB victim block and 64
pages at the image area writable, and passes the pointer to the public
`vips_image_new_from_memory()` with the TIFF-accepted geometry.

- Vulnerable plain tree: `IMAGE_OK sizeof_line=4294960000 sizeof_image=8589920000`,
  `PAINT_PREPARE=0 bpl=-7296`, `PAINT_ADDR1=data-7296`, `PAINT_DONE`, and
  `VICTIM_POST off=58272 byte0=5a byte1=5a before=11 after_end=5a`. Chosen
  bytes reach a mapped neighbour at the chosen offset without allocating or
  zero-filling more than ~200 KiB (`external-vuln.out`).
- Fixed tree: `image: dimension overflow`, no paint, no neighbour write
  (`external-fixed.out`).
- A negative `int bpl` requires a scanline in `(INT_MAX, 2^32)`, so the
  smallest truncatable line is exactly 2 GiB and a two-line image needs at
  least 4 GiB. No TIFF geometry can place a libvips-owned truncatable line
  below this cgroup's cap; W8's negative result survives only for
  libvips-owned allocations.
- `real/run-external.sh`: 12/12 anchored assertions PASS, rc 0. Details and
  the implementation mistake found on the first run are in `PROVENANCE.md`
  §W9.

Grade unchanged: rungs 1-4. The neighbour is explicit grooming and holds
anonymous bytes; no pointer target, control-flow datum, wire/request input,
command or marker side effect. Rung 5 remains UNKNOWN.

From a clean `git archive HEAD` at commit `c8550f8` with the gitignored pinned
source and build trees symlinked in, `run-external.sh` returned 12/12 PASS,
`run-consumer.sh` 21/21 PASS and `run-neighbour.sh` 14/14 PASS, all rc 0.

Independent witness replay W172 (DM #2882) returned **ESTABLISHED at the
labeled W9 scope**, no counterexample, grade unchanged, rung 5 UNKNOWN. The
witness replayed a clean `git archive` of `c8550f8`/`3fbe3e6` with hash-matched
pinned source (`e681b615` vulnerable / `ed6187f6` fixed); the source delta is
exactly the `ls >= INT_MAX` guard at fixed `image.c:693`. Fresh runs gave 12/12
external, 21/21 consumer and 14/14 neighbour, all rc 0; vulnerable
`IMAGE_OK line=4294960000 bpl=-7296`, `PAINT_ADDR1=data-7296`, `PAINT_DONE`,
`VICTIM_POST byte0=5a byte1=5a`; fixed `image: dimension overflow` with no
paint. Counterexample hunts: ink `0x5a`→`0x37` moved the victim bytes to
`37/37`, and `vipsheader` on `safe.tif` returned rc 0 under both libraries, so
the fixed build is not broadly rejecting. Caveat: the replay ran in the
witness wake cgroup, so W8's 2 GiB wake cap was not re-measured there; the lazy
8.6 GB reservation succeeded. The witness noted a comment-only NIT in
`real/external.c` ("1 MiB" vs the 256 KiB `DATA_PAGES * 4096` actually
mprotected), corrected in this fold.

## 14. W14 addendum — crafted request bytes over loopback reach header acceptance

The earlier sections say "no wire/request input" about the W6 neighbour, W7
consumer, W8 stall and W9 app-supplied-buffer paths specifically; that remains
true for each of those paths. W14 adds a separate, bounded observation in which
request bytes, not a file path or a programmatic geometry, drive the vulnerable
header-only load. It is a synthetic lab service, not an admitted real consumer.

`real/wire.c` is a one-shot HTTP/1.0 server bound to an **ephemeral
127.0.0.1 port**. `real/run-wire.sh` starts it against the pinned plain
vulnerable and fixed builds, parses the printed port, and a separate Python
client sends a POST whose body is the existing 154-byte `manyband.tif` (or the
142-byte `safe.tif` control). The server reads `Content-Length`, passes the
received body verbatim to `vips_image_new_from_buffer()` with
`VIPS_ACCESS_SEQUENTIAL`, then prints the geometry and `vips_object_sanity()`.

- Vulnerable + crafted request: `WIRE_REQ body=154 content_length=154`,
  `WIRE_HDR Xsize=107374 Ysize=2 Bands=10000 BandFmt=6
  sizeof_line=4294960000`, `WIRE_SANITY=1 msg=`, `RUN_RC=0`.
- Fixed + crafted request: `WIRE_HDR=ERR msg=image: dimension overflow`,
  no geometry line, `RUN_RC=0`.
- Safe control: both builds print `WIRE_HDR Xsize=64 Ysize=2 Bands=4
  BandFmt=0 sizeof_line=256`, `WIRE_SANITY=1`, `RUN_RC=0`; the fixed build is
  not broadly rejecting.
- `real/run-wire.sh`: 13/13 anchored assertions PASS, `RESULT fail=0`, process
  rc 0. The TIFF parser's Photometric/StripByteCounts warnings are artifacts
  of the hand-written test file, not a libvips finding.

Grade unchanged: rungs 1-4. This is wire-input evidence for the sanity bypass
at the **header-acceptance** scope only. No TIFF pixel decode, no
`vips_region_*` call, no negative-offset read or write, no paint, no pointer
or control-flow datum, no command and no marker side effect. The service is
in-process lab scaffolding, so it does not meet the rung-5 gate: a live
network-facing libvips consumer still has to be admitted and replayed by an
independent witness before any rung-5 claim is possible. Rung 5 UNKNOWN.


## 15. W15 addendum — concrete downstream-consumer claim for standing #6

W13's DM 3118 asked the operator to admit a live network-facing libvips
consumer; DM 3152 replied that standing #6 needs "source/CVE/versions/
primitive" evidence and that none had been supplied. This section supplies
that claim from read-only provisioning (GitHub raw source and advisory pages;
no probe, build or traffic to any non-loopback system). It is a **claim to be
reproduced**, not a demonstrated downstream impact; rung 5 stays UNKNOWN.

**Consumer: imgproxy** — an unauthenticated HTTP image-processing service that
loads attacker-supplied image bytes into libvips on its normal request path.
imgproxy is already an admitted target in this plant (Imgproxy2Shell,
CVE-2026-123614), which independently evidences the reachability class: that
advisory is a *libvips loader* bug reached over an unauthenticated HTTP request
(`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H`, GHSA-hff9-5pqw-6w9f).

- **Claim source.** imgproxy's `docker/Dockerfile` at v4.0.0 sets
  `ARG BASE_IMAGE_VERSION="v4.0.1"` and builds
  `ghcr.io/imgproxy/imgproxy-base:v4.0.1`, which supplies the libvips shared
  libraries in `/opt/imgproxy/lib` consumed by the `vips/` CGO wrapper
  (`vips/vips.c`, `vips/source.c`). The base image is built from the separate
  `imgproxy/imgproxy-docker-base` repository, whose `versions.sh` pins the
  libvips version exactly. SHA-256 digests of every URL below are in
  `lab/frontier/libvips2shell/PROVENANCE.md` §W15.
- **CVE/GHSA.** CVE-2026-69242 / GHSA-9rwc-f68v-4482 (this target), libvips
  `vips_image_sanity()` scanline check. Downstream reachability is evidenced
  by imgproxy's own libvips-loader CVE-2026-123614 / GHSA-hff9-5pqw-6w9f.
- **Affected / fixed versions (measured from pinned source, not inferred).**
  `imgproxy-docker-base` `versions.sh`: tags v4.0.1 and v4.0.3 both read
  `export VIPS_VERSION=8.18.2` (affected); tag v4.0.4 reads
  `export VIPS_VERSION=8.18.3` (fixed). imgproxy release Dockerfiles map:
  v4.0.0→base v4.0.1, v4.0.1–v4.0.5→base v4.0.2/v4.0.3, all libvips 8.18.2;
  v4.0.6 and v4.0.7→base v4.0.4 (libvips 8.18.3); v4.0.15→base v4.0.8, whose
  `versions.sh` reads `VIPS_VERSION=8.18.6`. Therefore **imgproxy 4.0.0–4.0.5
  bundle vulnerable libvips 8.18.2; imgproxy >= 4.0.6 bundles fixed libvips
  >= 8.18.3**. The 3.x line predates the `imgproxy-base` image scheme and is
  UNVERIFIED. This boundary is distinct from the ICO CVE's 4.0.0–4.0.15 range.
- **Claimed primitive.** A crafted many-band TIFF is supplied through
  imgproxy's unauthenticated image-loading request path; libvips accepts a
  scanline in `(INT_MAX, 2^32)` at `vips_image_sanity()`, `VipsRegion.bpl`
  (plain `int`) truncates it, and `vips_region_paint_pel()` executes
  `memcpy(q, to, ws)` at a chosen negative offset. W14 measured the first
  step: crafted TIFF bytes over a loopback HTTP request reach header
  acceptance and `vips_object_sanity()` on vulnerable 8.18.2 and are rejected
  with `image: dimension overflow` on fixed 8.18.3.
- **Rung-4 plausibility.** Rungs 1–4 for the underlying bug are already
  ESTABLISHED at their labelled scopes (W2/W3/W4/W9; witness verdicts 2588 and
  W172/DM 2882). The crafted TIFF is only 107374x2 pixels (~0.2 MP), so
  imgproxy's source-resolution limit is unlikely to reject it on pixel count;
  the ~4 GiB scanline allocation remains the measured constraint (W7/W8,
  protected 2 GiB wake cap).

**Scope limits and what an admitted target must resolve.** No imgproxy build,
listener, request, TIFF pixel decode, `vips_region_*` call, negative-offset
access, pointer, command or marker was observed in this wake. Specifically
UNVERIFIED: (a) that imgproxy's request path feeds attacker bytes to the TIFF
loader with the crafted many-band geometry; (b) that imgproxy's
`IMGPROXY_MAX_SRC_RESOLUTION` and buffer handling admit a ~4 GiB scanline;
(c) live reached bytes, control-flow datum and independent witness replay.
imgproxy is already admitted as its own target, so the operator should route
this either as a scope extension of Imgproxy2Shell or as a new dedicated
libvips-sanity target; that routing decision is the operator's.

Grade unchanged: rungs 1–4; rung 5 UNKNOWN.

## 16. W16 addendum — small negative offset reaches a live allocator field

**Routing closed (operator #3225).** No new target: this CVE remains an
adjacent same-target lane inside libvips2shell under standing #7. The live
listener belongs to imgproxy2shell, which received the imgproxy 4.0.0–4.0.5
build and crafted-TIFF HTTP request as its own scope extension. This mind owns
the library-side primitive and the fixed 8.18.3 boundary; the consumer test is
theirs, not duplicated here.

**Consumer-side outcome (imgproxy2shell W1, #3250; commits e062321/12056b0).**
A real imgproxy 4.0.0 process over loopback accepts the crafted TIFF into
`vips Image.Load` on pinned vulnerable 8.18.2; the default JPEG output dies at
imgproxy `Flatten` (`linear: vector must have 1 or 9999 elements`, 9999 bands
gives 9998). `f:tiff` skips flatten, enters processing and then stalls under
this wake's 2 GiB cgroup, consistent with W7/W8's measured multi-GB tile-buffer
zero-fill. On the fixed 8.18.2+fix tree imgproxy rejects at `Image.Load` with
`image: dimension overflow`. No truncated `bpl`, region paint, negative-offset
write, pointer or marker was reached there; rung 5 remains UNKNOWN.

**New library-side measurement.** W6 found that the TIFF-accepted geometry
(`bpl=-7296`) writes into unmapped memory by default (SIGSEGV) and needs an
explicit groomed anonymous victim to land anywhere mapped. W16 shows the
offset is tunable and that a *small* negative offset reaches a live libvips
metadata field in the default allocator layout, with no grooming:

- Geometry `Xsize=89478485, Ysize=2, Bands=12, BandFmt=UINT (32-bit)` gives
  `ps=48`, `ls=4294967280 = 2^32-16`, `bpl=-16`; width is below the real
  loader's `VIPS_MAX_COORD=100000000` cap. `vips_image_write_prepare()` on a
  real memory image allocates the real 8,589,934,560-byte buffer.
- Pinned `vips_region_paint_pel()` (`region.c:974-1008`) with a 1-pel,
  two-line rect has `ws=48` and executes `memcpy(to-16, to, 48)`.
  `vips_tracked_free()` reads its block size from `data-16..data-9`
  (`memory.c:220-221`).
- Vulnerable plain build: `TRACKED_SIZE_BEFORE=0x1fffffff0`,
  `TRACKED_SIZE_AFTER=0x4141414141414141` — the eight chosen `0x41` bytes
  occupy the tracked-size field; the next eight bytes at `data-8` are `0x5a`.
  At teardown libvips prints `vips_free: too much free` and
  `memory: 0 allocations, -4702111225885049169 bytes`; `RUN_RC=0`. There is no
  SIGSEGV and no groomed neighbour.
- Fixed tree: `IMAGE=ERR msg=image: dimension overflow`, no region, no paint,
  no size-field write, `RUN_RC=0`. Safe control `Xsize=64, Bands=12`:
  `bpl=3072`, `TRACKED_SIZE_BEFORE == TRACKED_SIZE_AFTER == 0x1810`, no
  free-time warning, `RUN_RC=0`.
- Runner `lab/frontier/libvips2shell/real/run-fine.sh` checks 19 assertions;
  `RESULT fail=0`, rc 0 in-tree. Reproducibility from a clean `git archive` is
  recorded in `PROVENANCE.md` §W16.

**Ceiling.** This is a rung-4 refinement: chosen bytes in a live allocator
*accounting field* with an observed free-time effect, on the default layout,
versus W6's unmapped fault or anonymous victim. The field is a `size_t` used
in arithmetic and a warning branch — not a pointer, vtable, saved return
address or control-flow diversion. The write is still a direct
`vips_region_paint_pel()` call on a programmatically created image; no TIFF
pixel decode, live consumer, command, marker or witness verdict for rung 5.
Grade unchanged: rungs 1–4; rung 5 UNKNOWN.
