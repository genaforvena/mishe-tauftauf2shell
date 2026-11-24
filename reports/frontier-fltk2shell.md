# Frontier brief — Fltk2Shell (CVE-2026-135433)

Status: **admitted 2026-11-24 05:4xZ under standing #6 as the 128th route;
rungs 1–4 ESTABLISHED by witness #3296 (W195) at the labeled direct-call
scope, NO rung 5.** Brief authored 2026-11-24 in wake W195; admission and
witness verdict folded in wake 2. Lab: `lab/frontier/fltk2shell/`.

## Claim ground truth (provisioning only, never a probe)

- CVE-2026-135433, published 2026-11-23 by VulnCheck, title "FLTK through
  1.4.5 Heap Buffer Overflow via Fl_BMP_Image Row Pointer" (<https://www.cve.org/CVERecord?id=CVE-2026-135433>).
  CNA description: crafted BMP/ICO image dimensions make the 32-bit row and
  alpha-mask pointer offsets wrap, writing file-derived pixel bytes out of
  bounds. CWE-190. CVSS 4.0 8.5 `AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H`;
  CVSS 3.1 7.8 `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`. Local file, user
  interaction, **no remote/network claim and no RCE claim** from the CNA.
  Credit: Matt Jesc (Nodejam). Affected: 0 through 1.4.5.
- Upstream issue <https://github.com/fltk/fltk/issues/1647> (opened
  2026-11-19, closed 2026-11-22) is the primary technical report. It includes
  a 118-byte BMP generator, an ASan driver, three geometries, logs and a
  maintainer-confirmed fix. Fix commit
  `a28e3927faebaba7d33f740d13e88fa0e22fd64d` ("BMP image loader: fix potential
  issue with crafted image file", 2026-11-21) touches one file,
  `src/Fl_BMP_Image.cxx`, +2/−2: casts the first factor of both row-pointer
  multiplies to `size_t`. Predecessor `3a049d8262dc759cf9737339420e8457e24c0cb1`
  (issue #1632 / CVE-2026-116724) bounds `colors_used` at 256 and sizes the
  allocation with `(size_t)`.
- Class fit: a widely embedded C++ GUI image loader; the constructor is the
  trigger, so opening an untrusted `.bmp`/`.ico` is enough. Ranked above the
  2026-11-24 FFmpeg advisory batch (FFmpeg already owned by this plant's
  staged targets) and above Dell Enterprise Sonic Distribution (no source).
  Threat model is strictly local plus UI — tractable, but not a server wire
  path.

## Source-bound mechanism (pinned bytes, not advisory prose)

Files pinned in `lab/frontier/fltk2shell/` with SHA-256 in `PINS.sha256`;
`run-all.sh` enforces the tarball pin, the other pins are provenance records.
The `gen_bmp.py` pin was stale (`a950ad4a…`) and is corrected in wake 2 to
the committed file's `69dd2a2a…`; see `PROVENANCE.md`.
Pinned `Fl_BMP_Image.release-1.4.5.cxx` is byte-identical to
`fltk-release-1.4.5/src/Fl_BMP_Image.cxx` in the upstream tarball.

- `:208-214` reads `width` and `height` as attacker-controlled signed 32-bit
  values from the BITMAPINFOHEADER; `:138` initialises `bDepth = 3`, `:273-274`
  sets it to 4 for 32-bit depth.
- `:280-285`: the guard `((size_t)width) * height * bDepth > max_size()` uses
  a wide product, but the allocation `new uchar[width * height * bDepth]`
  multiplies in `int`. `Fl_Image.H:393` shows `max_size()` defaults to
  `~(size_t)0`, so the guard does not stop gross geometry.
- `:303-304`: `for (y = start_y; y != end_y; y += row_order)` then
  `ptr = (uchar *)array + y * width * bDepth;` — the row pointer is another
  signed 32-bit multiply. `:509-512` repeats the expression in the
  alpha-mask loop. Both are the statements `a28e392` fixes on master
  (there named `dstBDepth`, a later rename).
- Geometry `width=2, height=715827883, depth=24`: `2*715827883*3 = 2^32+2`,
  so the allocation wraps to 2 bytes; with `row_order=-1` the first row is
  `y = 715827882`, whose `y*width*bDepth` wraps to −4, so the first pixel
  write lands before the allocation. The bytes written come from the file's
  pixel area through `rdr.read_byte()`.
- Claim discrepancy preserved: issue #1647 says commit `3a049d8` is
  master-only and absent from 1.4.5; the pinned `release-1.4.5` tag instead
  contains a different `max_size()` guard at `:280` while still lacking the
  256-entry colormap bound at `:257` and retaining the `int` allocation.
  Reproducing the row-pointer CVE alone therefore requires applying #1632's
  two edits by hand, exactly as the reporter did; this lab applies them via
  `plus1632.diff` in a separate tree.

## Local evidence (real FLTK 1.4.5 build, ASan, 118-byte files)

Built the upstream `release-1.4.5` tarball with CMake,
`-DCMAKE_CXX_FLAGS='-fsanitize=address -fno-omit-frame-pointer -g -O1'`,
`FLTK_BUILD_TEST=OFF`, and linked a small constructor driver against the
real `libfltk_images.a` + `libfltk.a`. `gen_bmp.py` emits the 118-byte files;
no exploit framework or external target was contacted.

| Rung | Observed | Case |
|---|---|---|
| 1 — trigger | `Fl_BMP_Image(const char*)` constructor parses the crafted BMP | `poc-alloc.bmp`, `poc-b.bmp`, `poc-c.bmp` |
| 2 — state failure (pristine tag) | nominal 4294967298-byte image allocated as 2 bytes (`new` at `:285`); ASan write 2 bytes before a 2-byte region | `poc-alloc.bmp` |
| 3 — corruption (pristine tag) | ASan `heap-buffer-overflow WRITE of size 1`, frame `:486` (24-bit) / `:499` (32-bit), constructor at `:64`; exit 134 | three attacks |
| 3 — isolated row-pointer CVE | with #1632 applied by hand the allocation is correctly 4294967298 bytes and ASan still reports a write 2 bytes before it at `:490` (24-bit) / `:503` (32-bit) | `plus1632` tree, three attacks |
| 4 — scoped impact | plain build under gdb at `:510`: chosen pixel bytes `53 49 4d 2d` ("SIM-") immediately before `array` and `45 48` inside it | `poc-chosen.bmp`, `gdb-chosen.txt` |
| control | safe 2×8 24-bit BMP loads clean (`fail=0`, exit 0); `a28e392`'s two casts make all five attack cases ASan-clean (exit 0, `fail=-3` from intentionally truncated pixel data) | `safe.bmp`, `plus1647` tree |

`run-all.sh` rebuilds all four trees, regenerates the fixtures, runs the
matrix and asserts **33 PASS / 0 FAIL**; normalized transcript `evidence.log`.
Clean `git archive 072dc75` replay rebuilt all four trees and repeated
33 PASS / 0 FAIL with a byte-exact normalized transcript
(`7882e60c…3525e`); the earlier `b214fbb` runner's different normalized hash
came solely from unmasked absolute paths. See `lab/frontier/fltk2shell/REPLAY.md`.
`evidence.log` sha256 is `71b373d0…d4d8c6`.

Witness #3296 (W195) independently replayed the four-tree matrix from a clean
`b214fbb` archive: all four trees rebuilt, `SUMMARY pass=33 fail=0`, and its
normalized transcript matched byte-exactly. Verdict: **ESTABLISHED rungs 1–4**
at the labeled direct-call / crafted-BMP-file / four-tree scope, NO rung 5.
ICO container, real GUI consumer, network surface, pointer/IP control and
command execution stay UNKNOWN.

Author-measured extension (wake 2, unwitnessed; evidence in
`lab/frontier/fltk2shell/shared-image/`): a headless consumer using the normal
`fl_register_images()` + `Fl_Shared_Image::get()` startup sequence reproduces
the identical isolated overwrite at `:490` through `fl_check_images` (exit
134, ASan `2 bytes before 4294967298-byte region`); the fixed tree is clean.
The ICO container is a clean negative under the tested geometry: its 8-bit
IconDirEntry width/height override the crafted DIB at `Fl_BMP_Image.cxx:201-205`,
so the row product never wraps; truncated and complete crafted ICOs load or
fail without ASan in both trees. This extends the rung-4 mechanics to the
standard shared-image API in-process. It is not a new witness verdict, a GUI
consumer, or a rung-5 claim.

## Ceiling and next experiments

Out of the ESTABLISHED scope: a GUI window / draw path or cache-hit reload,
a network-facing service, pointer/IP control, command execution, and rung 5.
The ICO path is now a measured negative, not an open positive lead. The
advisory's own impact is
local/UI-only, so server-style X2Shell reach is UNKNOWN and must not be
inferred. The chosen-byte result is a direct call into the real loader, not
an application-level exploit. Witness replay is complete (#3296); the
shared-image extension is author-measured only.

Next, per the operator's order: hand the shared-image extension to `witness`
if it is to become a claim, then consider a plain-build groom toward
pointer-sized metadata. Any new impact claim goes to `witness`; no RCE
inference from a heap OOB write. Wake units and full-flag sync remain the
person's.
