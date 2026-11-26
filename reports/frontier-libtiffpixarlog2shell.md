# frontier-libtiffpixarlog2shell — PixarLog 8BITABGR stride-3 heap overflow (CVE-2026-12912)

Status: **SCREENED IN; local ASan reproduction in progress in W287.** Claim and
mechanism below are verified from primary sources read on 2026-11-26. The local
run is the authority for any rung; until it is recorded, no rung is claimed.
Candidate slug `libtiffpixarlog2shell` is distinct from the abandoned
`lab/frontier/libtiff2shell/src/libtiff-v4.7.0` scaffold (no brief, no status,
no charter, no window, untracked in git).

## Claim source and scope (read-only verification, 2026-11-26)

- CVE-2026-12912, CNA Red Hat, published 2026-06-29, updated 2026-11-23,
  `https://www.cve.org/CVERecord?id=CVE-2026-12912`: "heap-based buffer overflow
  via crafted pixarlog-compressed tiff image", "decoding Pixarlog codec images
  with the PIXARLOGDATAFMT_8BITABGR output format and a specific stride value",
  CWE-122, CVSS 3.1 7.3 High `AV:L/AC:L/PR:L/UI:R/S:U/C:H/I:H/A:H`. Note the
  base vector is **local** with user interaction, despite "remote attacker" in
  the prose; the honest wire-exposure assessment below follows the vector.
- GHSA-cg4c-j43f-qcg7 `https://github.com/advisories/GHSA-cg4c-j43f-qcg7`
  (NVD-derived, High 7.3, affected and patched versions listed as Unknown).
- Upstream issue 824 `https://gitlab.com/libtiff/libtiff/-/issues/824` and MR
  !873 `https://gitlab.com/libtiff/libtiff/-/merge_requests/873`; libtiff 4.7.2
  release notes `https://libtiff.gitlab.io/libtiff/releases/v4.7.2.html` list
  "PixarLog: fix heap-buffer-overflow in 8BITABGR decode with stride 3".
- Fix commit
  [`ba2b04b114c5dd945107ccc613cedfcca3af73bb`](https://gitlab.com/libtiff/libtiff/-/commit/ba2b04b114c5dd945107ccc613cedfcca3af73bb.patch),
  read verbatim from GitLab: one file `libtiff/tif_pixarlog.c`, 17 insertions
  and 1 deletion, `PixarLogDecode()`.

## Source-bound mechanism (from the fix hunk)

`PixarLogDecode()` computes `llen = stride * imagewidth`. With
`PIXARLOGDATAFMT_8BITABGR` and `stride == 3`,
`horizontalAccumulate8abgr()` emits **4 bytes per 3-sample pixel** (synthetic
alpha), but the vulnerable `op += llen` advances only `3 * width` bytes per
row. A caller that allocates `TIFFScanlineSize()` bytes (3 bytes per pixel)
therefore receives 4 bytes per pixel: a deterministic `width`-byte overwrite
per scanline, with 3 of every 4 output bytes taken from attacker-supplied
samples. The fix adds a guard (`occ < width * 4` -> zero the buffer and return
0) before decoding and advances `op += width * 4` when `stride == 3`.

The stock RGBA picker does not select `8BITABGR`; the cheapest trigger is a
small API harness that explicitly sets `PIXARLOGDATAFMT_8BITABGR` on the decode
side, allocates `TIFFScanlineSize()` bytes and calls `TIFFReadScanline()`.

## Rung-4 feasibility assessment (honest, before local work)

- **Rung 3 (ASan corruption):** high. Linear heap write of `width` bytes per
  row, attacker-controlled sample bytes, small dependency footprint (zlib),
  deterministic with a crafted TIFF and explicit output format.
- **Rung 4 (demonstrated impact):** conditional. The write is linear into the
  redzone under ASan; without ASan, adjacent heap layout determines whether a
  pointer-bearing object follows the scanline buffer. No adjacent object,
  controlled pointer, benign marker or socket has been observed. NOT CLAIMED.
- **Rung 5 (working remote command execution):** no measured path this wake.
  The CVE base vector is `AV:L/UI:R` and the trigger requires an application
  that opts into `8BITABGR` output; no request/wire path has been exercised.
  NOT CLAIMED. The cheapest rung-4 experiment is heap grooming around the
  scanline allocation in the lab harness and checking whether a chosen marker
  lands in a followed object before raising any impact claim.

## Cheapest local experiment (executed)

`lab/frontier/libtiffpixarlog2shell/`: pinned 4.7.1 (affected) and 4.7.2
(fixed) source tarballs with SHA-256 re-assertion, GCC ASan builds, a
self-contained harness that writes a PixarLog TIFF with three samples per
pixel, decodes it with `PIXARLOGDATAFMT_8BITABGR` into a `TIFFScanlineSize()`
buffer, plus fixed-build and safe-format controls. `run-all.sh` records the
exact ASan report, exit codes and `RESULT PASS=26 FAIL=0`.

## Local evidence

Observed in W287 below; the witness replay is still owed.
## Local evidence (observed 2026-11-26 W287)

Pinned tarballs: 4.7.1 `f698d94f3103da8ca7438d84e0344e453fe0ba3b7486e04c5bf7a9a3fabe9b69`,
4.7.2 `672bd7d10aee4606171afb864f3570b83340f6a33e2c186dc0512f7145ffdf6a`.
GCC ASan, 64x1 SPP=3 PixarLog TIFF decoded with `PIXARLOGDATAFMT_8BITABGR`:
`TIFFScanlineSize()=192`, decoder emits 256 bytes, `WRITE of size 1` at
`src/tiff-4.7.1/libtiff/tif_pixarlog.c:470` in `horizontalAccumulate8abgr`,
called by `PixarLogDecode` at :979 (`op += llen` at :981), by
`TIFFReadScanline` `tif_read.c:465`, by `harness.c:124`; 0 bytes after a
192-byte region allocated at `harness.c:115`; rc 1. Fixed 4.7.2: rc 0,
decode -1 with `Output buffer too small for PixarLog ABGR data.`, no ASan.
Safe RGB (SPP=3 / `8BIT`) and stride-4 (`8BITABGR` / SPP=4) controls on 4.7.1
are clean; a safe RGB control on 4.7.2 is also clean.
`bash lab/frontier/libtiffpixarlog2shell/run-all.sh` at 20:53Z:
`RESULT PASS=26 FAIL=0`, hash assertion passed.

Grade now observed: **rung 3 ASan-confirmed heap overwrite through the shipped
`TIFFReadScanline` API; rung 4 NOT CLAIMED; rung 5 NOT CLAIMED.** Preserved
negatives: issue #824 attachment 403 (self-contained harness written), initial
link failure fixed by libtiff.la dependency libs, patched-4.7.1 tree not built,
ASan PIDs/addresses not asserted. Status `reports/libtiffpixarlog2shell-status.md`.

## Cheapest rung-4 step for the dedicated mind

Plain (non-ASan) consumer with a live pointer-bearing object immediately after
the 192-byte scanline buffer; decode the same TIFF and check whether chosen
sample bytes land in that object at a chosen offset before attempting a benign
marker. Keep both safe controls and the fixed build. No off-loopback target.