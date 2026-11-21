# Frontier brief — Pillow FlashPix JPEG scanline write (Pillow2Shell)

**Status: new frontier find, brief + harness COMPLETE (2026-11-21 ~12:40Z) —
pending independent witness replay and operator admission.** Rungs 1/2/3 are
ESTABLISHED in an extracted, verbatim-pin C harness; rung 4 shows real
libjpeg-decoded, attacker-value bytes at chosen offsets past a tile-sized
buffer. No FPX file, OLE2 parser, Pillow build, image-upload server, socket,
real Python heap neighbour, pointer, control-flow diversion or execution was
observed — all stay UNKNOWN. The advisory's "arbitrary code execution" is a
claim to reproduce, not a result obtained here.

## Verified ground truth (claim sources + this lab, 2026-11-21)

- **Advisory**: CVE-2026-112398 / GHSA-5x8w-8jj5-q52h / PYSEC-2026-4330; CNA
  GitHub_M, reporter Alex Bouffard (pebwalker). CVE `datePublished`
  `2026-10-19T21:07:25.229Z`, `dateUpdated` `2026-10-22T21:06:17.285Z`.
  Verbatim CNA text: "Prior to 13.0.0, Pillow's FlashPix JPEG-tile decoder can
  write decoded scanlines beyond the allocated tile buffer. FlashPix (FPX)
  JPEG decoding selects raw mode LA with two bytes per pixel, while an
  unrecognized JPEG mode can be decoded as JCS_UNKNOWN with four components,
  causing ImagingJpegDecode to write four-component scanlines into the
  two-byte tile buffer. An attacker can supply a crafted OLE2 FlashPix file to
  an application with the optional olefile dependency installed that opens or
  thumbnails untrusted input. This can corrupt heap memory and may allow
  arbitrary code execution." CVSS 4.0
  `AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N` = **9.2 CRITICAL**;
  CWE-122/CWE-787. Pins: `src/cve112398.json`, `src/ghsa-5x8w-8jj5-q52h.html`;
  sources <https://cve.org/CVERecord?id=CVE-2026-112398>,
  <https://github.com/advisories/GHSA-5x8w-8jj5-q52h>,
  <https://osv.dev/vulnerability/CVE-2026-112398>.
  The GHSA HTML pin is a snapshot, not reproducible byte-for-byte on re-fetch
  (dynamic metadata IDs change; advisory text semantically identical); see
  `lab/frontier/pillow2shell/PROVENANCE.md`.
- **Affected/fixed**: CVE says `< 13.0.0`, GHSA says `<= 12.3.0`; raw tag
  `12.2.0` was verified vulnerable here and raw tag `13.0.0` carries the
  guard. Fix commit `242a059aedc1935097d9aa1dc3f099750467ba75` ("Reject JPEG
  streams whose scanlines are wider or have more components", PR #10131,
  2026-10-06) adds 11 lines to `src/libImaging/JpegDecode.c` and a regression
  test; pinned in `src/fix112398.patch`.
- **Raw sources**: `src/libImaging/JpegDecode.c` at `12.2.0` (affected) and
  `13.0.0` (fixed), `src/decode.c` and `src/PIL/FpxImagePlugin.py` at `12.2.0`,
  plus the patch, CVE JSON and GHSA page — seven SHA-256 pins in
  `lab/frontier/pillow2shell/PROVENANCE.md`, re-verified by `gen_driver.py` on
  every run (pin drift: `gen_driver.py` exits 1, `run.sh` exits 2).
- **This lab**: extracted C driver with fault statements copied byte-for-byte
  under `#line`; real libjpeg decodes a 4-component CMYK JPEG, a local row-copy
  shim hands that row to the pinned `jpeg_read_scanlines` call. 10 PASS /
  0 FAIL, ASan `WRITE of size 256` from the pinned `:252` caller, chosen
  `0x5a`/`0xa5` at offsets 0/16/32/48 for three tile limits, guard-page fault,
  fixed/benign ASan-clean.

## Source-bound mechanism

Line numbers are from raw pinned bytes, tag `12.2.0` unless marked fixed.

1. `FpxImagePlugin.py:25/30` maps the attacker's FPX image-contents colour IDs
   to rawmode `"LA"` (2 bytes/pixel); the operative assignment is `:113`
   (`self._mode, self.rawmode = MODES[colors]`) and `:201` leaves
   `jpegmode=None` when the ID is unrecognised.
2. `decode.c:223` computes `state->bytes = (state->bits * state->xsize + 7)/8`
   from the tile extents and rawmode, and `:226` allocates exactly that many
   bytes. For a 32-pixel tile and `"LA"`, `state->bytes = 64`.
3. The rawmode fallback block `JpegDecode.c:209-222` ends at `:220-221`,
   where both `jpeg_color_space` and `out_color_space` are set to
   `JCS_UNKNOWN` for the unrecognised jpegmode/rawmode, disabling decoder
   conversions. A 4-component JPEG (CMYK in the harness)
   survives as four output components; `jpeg_start_decompress` at `:240`
   accepts it.
4. `:252` calls `jpeg_read_scanlines(&context->cinfo, &state->buffer, 1)`
   with no width/component check. libjpeg writes `output_components *
   output_width` bytes (256 here) into the 64-byte tile buffer — 192 bytes
   past it. The decoded byte values come from the attacker's JPEG coefficients.
5. Fixed `13.0.0:247-253` rejects `output_width > state->xsize` or
   `output_components * output_width > state->bytes` before `state->state++`
   and before the scanline (now `:263`). The patch hunk adds exactly that
   guard plus the regression test.

## Lab evidence

`cd lab/frontier/pillow2shell && bash run.sh <outdir>`:

- A clean `git archive f44a538 lab/frontier/pillow2shell` extraction into
  `/tmp/pw2-archive`, replayed with an absolute outdir `/tmp/pw2-out`, gave the
  same 10 PASS / 0 FAIL rc 0 and the same digest in both five-run groups.
- 10 PASS / 0 FAIL, exit 0. Two independent five-run groups both
  `sha256=cb758c07f0aec3620c7b0d14c0fd471bf6b1455c410ead291db7a57eb08d818b`.
- Rung 1: `rv=1 limit=64 staged=256 stag0=5a` — a 4-component row of 256 bytes
  is delivered to a 64-byte tile buffer.
- Rung 2: `oob0=5a oob16=5a oob32=5a oob48=5a` with the next in-bounds slot
  intact; an independent `0xa5` encoding gives the same four offsets as `a5`.
- Rung 3 (ASan): `heap-buffer-overflow`, `WRITE of size 256`, frame
  `pillow_row_copy` called from `JpegDecode_v12.2.0.c:252` — the verbatim
  pinned scanline statement.
- Rung 4 (INSTRUMENTED chosen-byte control): `0x5a` read back at offsets
  0/16/32/48 for tile limits 16, 32 and 48 (buffers 32/64/96 bytes, rows
  128/256/384 bytes); `0xa5` independently. The bytes come from real libjpeg
  decoding of a value-chosen, flat, quality-100 JPEG (DCT round-trip was
  checked byte-exact), not from a fixed marker in the harness.
- Guard page: the first past-end store faults SIGSEGV (rc 139).
- Fixed `13.0.0`: hostile input returns `rv=-1` before any write; a scanline
  that fits (32-pixel JPEG into a 64-pixel tile) returns `rv=1` with the last
  in-bounds byte `41`. Vulnerable benign, fixed hostile and fixed benign ASan
  runs are clean — counterexamples against an oracle that flags every input.

**Harness boundary, stated plainly**: the WRITE observed by ASan is the local
row-copy shim's `memcpy`, not libjpeg's own stores — the host libjpeg is not
ASan-instrumented. Byte values and row length are produced by that real
libjpeg decode, and the caller line, buffer sizing and fallback are verbatim
pinned bytes; the shim models the destination handoff only. ASan leak checks
are disabled in `run.sh` because the extracted driver intentionally does not
free scaffolding allocations.

## Rung-4 feasibility assessment

The primitive is a chosen-content, chosen-length heap write: an unauthenticated
image-processing consumer calling `Image.open().load()` on attacker bytes is
the advisory's claimed path. In the lab the decoded bytes land at chosen
offsets past the tile-sized buffer (rung 4 INSTRUMENTED). Beyond that nothing
is established: no OLE2/FPX front end ran, no Pillow process or Python object
was corrupted, no chunk metadata, adjacent object, pointer or function pointer
was overwritten, and no control flow was diverted. The advisory's full exploit
needs an ASLR-disabled non-PIE pinned image, an iterative lossy-JPEG byte
convergence loop, an adjacent `bytes` object and a `system@plt` address — all
UNKNOWN here and out of scope for this extracted driver. Whether the local
libjpeg version matches Pillow's bundled decoder byte-for-byte is also
UNKNOWN; the harness uses the host libjpeg only.

**Cheapest rung-raising experiment**: build Pillow `12.2.0` and `13.0.0` with
ASan and `olefile` installed, build a minimal FPX file whose tile rawmode is
`"LA"` with an unrecognised JPEG mode and a 4-component wider JPEG, then run
`python3 -c 'from PIL import Image; Image.open("case.fpx").load()'` on a loopback
host. Expect an ASan WRITE inside `jpeg_read_scanlines` from
`ImagingJpegDecode` at pinned `JpegDecode.c:252`, and no write at `13.0.0`.
Before any pointer or marker claim, freeze the first past-end bytes and inspect
the real Python heap neighbour under gdb. That work belongs to a dedicated
target mind after admission, not this extracted-driver lane.

## Scope and boundaries

Loopback-free local process drivers: no FPX file, OLE2 parse, Pillow build,
socket, server or external probe. Sources were fetched read-only as
provisioning. Harness stand-ins and exact copied ranges are enumerated in
`PROVENANCE.md`. No nginx or other plant's lane was touched.
