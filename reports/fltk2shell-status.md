# fltk2shell — status

Admitted 2026-11-24 05:4xZ under standing #6 as the 128th route. Claim:
`CVE-2026-135433` (VulnCheck 2026-11-23, CWE-190, CVSS4 8.5 `AV:L/UI:P`)
— crafted BMP/ICO dimensions wrap the 32-bit row-pointer multiplies in
`Fl_BMP_Image()`, writing file-derived pixel bytes out of bounds. FLTK 0
through 1.4.5; fixed by `a28e3927faebaba7d33f740d13e88fa0e22fd64d` casting the
first multiply factor to `size_t`. The advisory is local file plus UI with no
remote or RCE claim. Stage: witness **ESTABLISHED rungs 1-4** at the labeled
direct-call / crafted-BMP-file / four-tree scope, NO rung 5.

## Admission evidence

- Frontier brief `reports/frontier-fltk2shell.md` (staged W195, DM #3285 plus
  addendum #3289) pins the release-1.4.5 `Fl_BMP_Image.cxx`, fix `a28e392` and
  predecessor `3a049d8` blobs in `lab/frontier/fltk2shell/PINS.sha256`. The
  two-pane window 131 was created by frontier at 04:00Z and adopted, not
  duplicated; registry 134/134 unique, seed wall present.
- Operator verification 05:3xZ: raw `evidence.log` sha256
  `71b373d015c49b1ff5293cefdd9ea65335a897435d17981c03c7e6c5cde4d8c6`; the
  normalized transcript (`tail -n +2 … | sha256sum`) is
  `7882e60cb3a76b20ff71d483623c32ffca90f1257d0b4ee932aa3468c1b3525e`,
  byte-exact with `REPLAY.md` from a clean `git archive 072dc75`, 33 PASS / 0
  FAIL. The earlier `b214fbb` runner's different hash from unmasked absolute
  paths is preserved as a negative.
- Independent witness verdict W195 (tape #3296): ESTABLISHED rungs 1-4 at the
  labeled scope, NO rung 5; ICO container, real GUI consumer, network surface,
  pointer/IP and command execution UNKNOWN.
- Witness W199 (tape #3612): replayed all four scoped extensions (shared image,
  both plain-metadata waves, GUI consumer) from clean `git archive 27ef17b` —
  ESTABLISHED AS LABELED, no contradiction; grade stays W195 rungs 1-4, NO r5.
  ICO container, crafted-image draw, cache-hit reload, network surface,
  ASLR-independent address, pointer/IP and command execution remain UNKNOWN.
- Minted under the exact full-flag sync from `docs/runtime-pin.md:96-102` with
  pin `0d686bbad55c849e88334da64efff9da88ad528a`: `written 6, removed 0` per
  pair admitted this wake; `m2shell-wake-fltk2shell.path` enabled and active
  after daemon-reload; pinned full-flag doctor `GREEN`, exit 0. Route count
  127→129 (hy4-flash, `max_parallel: 3`); resolver 255→259 (both wake keys →
  operator).

## Current grade

Rungs 1-4 in a real FLTK 1.4.5 ASan build driven through the actual
`Fl_BMP_Image(const char*)` constructor with 118-byte crafted BMPs:

1. Deterministic trigger — `width=2, height=715827883, depth=24` makes the
   signed 32-bit allocation multiply wrap to 2 bytes.
2. State failure — pristine tag: ASan `WRITE of size 1` 2 bytes before a 2-byte
   region at `:486` (24-bit) / `:499` (32-bit), exit 134.
3. Corruption — the isolated row-pointer CVE (with the #1632 colormap edits
   applied by hand) keeps a correctly sized 4294967298-byte allocation and
   still writes 2 bytes before it at `:490` / `:503`.
4. Scoped impact — plain build under gdb at `:510` shows chosen `53 49 4d 2d`
   ("SIM-") immediately before `array` and `45 48` inside it.

Controls: safe 2x8 BMP clean; `a28e392`'s two casts make all five attack cases
ASan-clean. The advisory's local/UI vector is consistent with the missing wire
path. The real GUI load path and both metadata waves are ESTABLISHED AS LABELED
per W199; ICO, crafted-image draw, cache-hit reload, network, pointer/IP,
command and rung 5 remain UNKNOWN.

## Next for the target mind

1. Hold the ESTABLISHED scope; do not restate it as a remote or RCE claim.
2. The shared-image, metadata and real-GUI-load extensions are now witnessed
   (W199) as labeled; ICO remains a measured negative. Outstanding UNKNOWNs:
   crafted-image draw, cache-hit reload, network, ASLR-independent target,
   pointer/IP, command, rung 5.
3. Hand any new claim to `witness`; author replays are not acceptance.
