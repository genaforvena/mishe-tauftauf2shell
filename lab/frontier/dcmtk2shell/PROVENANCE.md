# Provenance — DCMTK 3.7.1 JPEG encoder planar-configuration OOB write (CVE-2026-133168)

Read-only provisioning only. No probe, connection or traffic to any non-loopback
system. Every upstream source below was fetched from its public host and stored
verbatim in `src/`.

## Claim sources

| Source | URL | local file | SHA-256 |
|---|---|---|---|
| GHSA advisory | https://github.com/advisories/GHSA-vhjh-fq99-4gmr | — (read via tool) | — |
| CVE record | https://www.cve.org/CVERecord?id=CVE-2026-133168 | — (read via tool) | — |
| VulnCheck advisory | https://www.vulncheck.com/advisories/dcmtk-3.7.1-heap-buffer-overflow-via-jpeg-encoder-planar-configuration-conversion | — (read via tool) | — |
| DCMTK issue #1298 | https://support.dcmtk.org/redmine/issues/1298 | — (referenced by fix commit) | — |

Advisory facts: CNA VulnCheck, published 2026-11-19; CWE-787, CVSS 4.0
8.5 High (`AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`);
affected DCMTK 3.7.1; fixed by commit `c22836c` (no patched release number in
the GHSA at read time). Credit in the fix commit: Peter Klotz and Federico
Muttis (Diphrakt B.V.).

## Pinned source and fix artifacts (verbatim)

| Artifact | URL | local file | SHA-256 |
|---|---|---|---|
| vulnerable `djcodece.cc` @ tag `DCMTK-3.7.1` | https://raw.githubusercontent.com/DCMTK/dcmtk/DCMTK-3.7.1/dcmjpeg/libsrc/djcodece.cc | `src/djcodece_v3.7.1.cc` | `e6577f1f430a5e6cb91cb74274ebd01d643a159148b585fce75f07953a76cc60` |
| fixed `djcodece.cc` @ `c22836c449bb81834fee5d883e9ebd9d7dab90b9` | https://raw.githubusercontent.com/DCMTK/dcmtk/c22836c449bb81834fee5d883e9ebd9d7dab90b9/dcmjpeg/libsrc/djcodece.cc | `src/djcodece_fixed.cc` | `e76e74ee85c84688f2e37b6c8deb0ffb2e044c749d959c790c59281f45194218` |
| fix patch `c22836c` | https://github.com/DCMTK/dcmtk/commit/c22836c449bb81834fee5d883e9ebd9d7dab90b9.patch | `src/fix_c22836c.patch` | `ba676231a705e2392f2d064606229758c327235d495ea45ee601cf33156d277a` |

The fix commit subject is "Fixed stride calculation when changing planar
config." (Marco Eichelberg, 2026-11-01); it closes issue #1298 and says the bug
was introduced by the attempted fix to issue #1285 in DCMTK 3.7.1. The upstream
GHSA points at `DCMTK-3.7.1/dcmjpeg/libsrc/djcodece.cc#L1503-L1540`.

## Harness pins

| Artifact | SHA-256 |
|---|---|
| `gen_driver.py` | `6edab5b6aa9eac33794e8320b2101d06e193b625b49cab81288e959305fea3b0` |
| `normalize.py` | `db73a1f897900f90935671a4a8ee82eab6c2e703c62af96f7c40f3de9eb672c4` |
| `run.sh` | `cca4eb2b3a02acad539046196d33efdd189f9d20be9561609f06d3d8d90d2620` |

`gen_driver.py` verifies all three upstream pins, then extracts the completely
verbatim `DJCodecEncoder::togglePlanarConfiguration8()` body from each pinned
file under a `#line` directive pointing at that file and its true line number.
The compiled function is the pinned source; only the type stubs and driver are
synthetic. Any pin drift aborts before compilation.

## Source-bound mapping (line numbers from the pinned files)

- `src/djcodece_v3.7.1.cc:1491-1552` — vulnerable `togglePlanarConfiguration8()`:
  `new Uint8[numValues]` at 1503, `pxPerFrame = columns * rows` at 1506, buggy
  `r_x_rows = r * rows` at 1519 and 1536, past-end writes at 1525 and 1540,
  `memcpy(pixelData, px8, numValues)` at 1549.
- `src/djcodece_v3.7.1.cc:598` — caller guard rejects only
  `bytesAllocated * samplesPerPixel * columns * rows * frames > length`; calls
  at 620 and 736 pass `length` as `numValues`. Declared `length` may exceed the
  true per-frame size.
- `src/djcodece_v3.7.1.cc:1555-1617` — 16-bit twin with the same stride bug.
- `src/djcodece_fixed.cc:1491-1541` — fixed function: `totalValues` computed at
  1502, `numValues < totalValues` guard at 1503, flat index `i` with correct
  stride at 1520/1530, `memcpy(..., totalValues)` at 1538.

## Replay

`bash lab/frontier/dcmtk2shell/run.sh <outdir>` prints `8 PASS / 0 FAIL`,
`ALL CHECKS PASS rc 0`, and a five-run digest
`sha256=03eb9e16ef2f16d64b4ef0d1b1f77f6549f885752debe15a050f5810fc970649`.
The trace normalizer emits no PID, address or path text, so replays are
byte-identical. All sockets are in-process; no live DCMTK process is started.
