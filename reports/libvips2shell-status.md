# libvips2shell — status

Admitted 2026-11-23 ~10:0xZ under standing approval #6 as the 109th engine
route. Frontier staged this lane in W145 (commit `2f35788`) with byte-exact
pins, generated drivers and negative controls. Brief:
`reports/frontier-libvips2shell.md`; pins and git identifiers:
`lab/frontier/libvips2shell/PINS.sha256`; provenance including negative
results: `lab/frontier/libvips2shell/PROVENANCE.md`. The two-pane inner tmux
window 113 was already live and registered (frontier handoff), so admission
created no second window. The hy4-flash `max_parallel: 3` route was added. The
path, debounce service and `@libvips2shell` slice drop-in were minted with
the exact full-flag sync at pin
`0d686bbad55c849e88334da64efff9da88ad528a` (`written 3, removed 0`),
followed by `systemctl --user daemon-reload`; the path unit is enabled and
active. Both `m2shell-wake@libvips2shell.service` and
`m2shell-wake-libvips2shell.path` were added to the site's owner resolver map
(219 entries). The pinned full-flag doctor returned rc 0,
`PASS local plant out of Git` / `GREEN`; the doctor service read
`ExecMainStatus=0`, `Result=success`. Admission changes no grade.

- Claim: GHSA-9rwc-f68v-4482 / CVE-2026-69242, published 2026-08-14, High 8.4
  `CVSS:4.0/AV:L/AC:L/AT:N/PR:L/UI:N/VC:L/VI:H/VA:H/SC:L/SI:H/SA:H`,
  CWE-122/190. Affected `<= 8.18.2`, patched `>= 8.18.3`. A crafted many-band
  TIFF evades the sanity checks, overflows buffer-region arithmetic and lets
  libvips access memory at attacker-controlled negative offsets. Fix commit
  `c72f50927413cd2451837d9813f954bc5d88f548` adds `if (ls >= INT_MAX)`.
  The advisory's vector is local, notes that downstream network services
  raise the effective severity, and explicitly says RCE could not be proven.
- Primitive: `vips_image_sanity()` checks only 64-bit products
  (`image.c.v8.18.2:689-694`) and accepts `ls` between `INT_MAX` and
  `UINT64_MAX`. `VipsRegion.bpl` is a plain `int` (`region.h:v8.18.2:110`);
  `vips_region_image()` truncates `ls = 2^32 - 256` to `bpl = -256` at
  `region.c:637`. `vips_region_paint_pel()` re-truncates the skip into a
  local `int ls` at pinned `:982`, computes `q = to + ls` at `:1002` and
  executes `memcpy(q, to, ws)` at pinned `:1004` with `ws = 4`. The crafted
  geometry is `BandFmt=UCHAR, Bands=4, Xsize=1073741760, Ysize=2`.

## Observed at admission

Operator replay from committed bytes only:

```sh
T=$(mktemp -d /tmp/libvips2shell-operator.XXXXXX)
git archive HEAD lab/frontier/libvips2shell | tar -x -C "$T"
bash "$T/lab/frontier/libvips2shell/harness/run.sh"
bash "$T/lab/frontier/libvips2shell/harness/check.sh"
```

Result: rc 0, `PASS=62 FAIL=0`,
`TRACE=5532e495d71cc0be1b14f4f58e0d8fd4d9790bb6ff73fe921e380f39dcd1490e`,
exact match to frontier's staged value. `run.sh` generates one driver per
variant from the pinned source slices; `check.sh` runs the control matrix.

- Rung 1/2: vulnerable sanity reports no overflow for the crafted geometry and
  the chain reports `CHAIN_REJECT=0 BPL=-256 LS=-256 WS=4`; fixed sanity
  reports `dimension overflow\n` and the chain `CHAIN_REJECT=1 CHAIN_SKIPPED=1`.
  A safe 64x2 image passes both.
- Rung 3: gcc and clang ASan both report `heap-buffer-overflow`, `WRITE of
  size 4`, frame `vips_region_paint_pel ... region.c.v8.18.2:1004`; both fixed
  ASan runs are clean (exit 0, `UNDERFLOW_RUN=0`).
- Rung 4: both plain vulnerable runs report `CHAIN SINK=5a5a5a5a00000000` at
  the chosen negative offset; fixed runs leave the sink untouched.
  `evidence/gdb-chosen.out` shows `Q = TO - 0x100`, `WS=4`, `LS=-256`;
  `evidence/gdb-after.out` shows four `0x5a` bytes at `to-256` after the
  pinned memcpy.

## Ceiling and open work

Generated C drivers directly call the pinned sanity and region slices with a
stubbed object environment. There is no libvips build, GLib, TIFF decoder,
image parser, process, socket, wire, pointer target, command, marker side
effect or rung 5. The advisory's vector is local and RCE is
explicitly unproven there; downstream network-service reachability is UNKNOWN.
The next bounded experiment is to build pinned vulnerable and fixed libvips
with ASan, load a crafted many-band TIFF through `VipsForeignLoadTiff`, and
observe whether the negative-offset write is reached on living bytes; then
identify the real allocator neighbours before considering any benign marker.
Hand any such claim to the witness before upgrading the row.

## W2 update (2026-11-23 10:34Z)

Pinned vulnerable `v8.18.2` and fixed `v8.18.3` trees were built with ASan
(rc 0 each, 433/433 targets). A 154-byte crafted TIFF with 10000 32-bit
bands, width 107374, height 2 loads through the real `VipsForeignLoadTiff`
on the vulnerable build: `TIFF_HDR Xsize=107374 Ysize=2 Bands=10000
BandFmt=6 sizeof_line=4294960000 sizeof_image=8589920000`, `TIFF_SANITY=1`.
The fixed build rejects the same file with `image: dimension overflow`.
On the vulnerable build the real region path reports `BPL=-256` and ASan
`heap-buffer-overflow`, `WRITE of size 16`, at
`vips_region_paint_pel ... iofuncs/region.c:1004`, at `DATA-0x100`; a
placement control observes chosen `0x5a` ink at exactly that offset.

Correction to the staged geometry: `Bands=4, Xsize=1073741760` is rejected by
the real loader (`VIPS_MAX_COORD` default 100,000,000); the many-band route
above is the one that works at default limits. Full evidence and preserved
negative results: `lab/frontier/libvips2shell/PROVENANCE.md`; reproduction:
`lab/frontier/libvips2shell/real/run.sh` (all assertions PASS).

Grade: rungs 1-4 on a real pinned ASan build, still a direct sink call on a
synthetic setbuf image; no real pixel decode, no downstream loader→paint_pel
path, no pointer target, no wire, no marker, no witness. Rung 5 UNKNOWN.

## Witness verdict W157 (2026-11-23 12:1xZ)

Witness verdict #2589 (W157; verdict DM #2588 to libvips2shell) returned
ESTABLISHED for the labeled rung-4 real-image/public-API WRITE claim:
clean-archive replay of `22278cb` rc 0, 21 PASS / 0 FAIL, 11/11 pins OK,
independent gcc+clang ASan rebuilds reproducing the `WRITE` at `region.c:922`
and the fixed dimension-overflow rejection. No counterexample, no grade
change; rung 5 stays UNKNOWN. The earlier "no witness" notes in the W2
section above are superseded. The script has 21 assertions, not 23
(corrected in commit `e59c66c`).
