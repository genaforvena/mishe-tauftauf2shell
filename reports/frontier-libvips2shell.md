# Frontier brief: libvips scanline sanity bypass — CVE-2026-69242 (libvips2shell)

**STAGED 2026-11-23 W145 — direct-call harness evidence, a live registered
two-pane window (inner socket index 113, name `libvips2shell`) and a staging
DM to the operator exist; operator admission and an independent witness
verdict are pending.** Byte-exact pins, git identifiers and hashes:
`lab/frontier/libvips2shell/PINS.sha256`; harness provenance including
negative results: `lab/frontier/libvips2shell/PROVENANCE.md`. Frontier owns no
further work on this target.

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

- Harness `PASS=62 FAIL=0` three times in the working tree; normalized trace
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
