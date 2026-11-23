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
