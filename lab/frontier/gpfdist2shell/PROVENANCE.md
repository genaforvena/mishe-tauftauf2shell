# PROVENANCE — gpfdist2shell (CVE-2026-122042)

All sources below were fetched read-only from public origins on 2026-11-21;
nothing outside loopback was probed or contacted with a trigger.

## Upstream pins (SHA-256 of the exact bytes stored in `src/`)

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `src/gpfdist_v7.6.1.c` (affected) | `https://raw.githubusercontent.com/warehouse-pg/warehouse-pg/7.6.1-WHPG/src/bin/gpfdist/gpfdist.c` | `deb74f328500585bc9145fdb02d995be80e33103566f1b7ca83f81d1ef3ea0d2` |
| `src/gpfdist_v7.6.2.c` (fixed) | same path at tag `7.6.2-WHPG` | `0f328ca0e823bb49af637e2e223858f84b44e49a84def24ec4bd86a6184f62ac` |
| `src/pr370.patch` (WarehousePG 7 fix) | `https://github.com/warehouse-pg/warehouse-pg/pull/370.patch` | `ca71aa292db5a6d534bcda73d850f2e5a78da719fc22fb4970572caa09a4b0b5` |
| `src/advisory.md` (vendor advisory, `.md` suffix) | `https://www.enterprisedb.com/docs/security/advisories/cve2026122042.md` | `061af07bf4b659af01e2bdf13305225b5ef3f2f939b787c9d3dab938bd18b602` |

Fix PR `warehouse-pg/warehouse-pg#370`, merged
`6fbb42ed6480bf3534c0a49e5f251dff468e8469` 2026-10-30T01:02:21Z into `main`;
the companion WarehousePG 6 PR is #371. Advisory: CVE-2026-122042,
CVSS 4.0 7.1 High `AV:A/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`,
CWE-787/CWE-129, affected 6.27.1–6.27.7 and 7.2.1–7.6.1, fixed 6.27.8/7.6.2.

## Source-bound statements copied verbatim by `gen_driver.py`

Each statement below is emitted under a `#line` marker pointing at its exact
line in the pinned file; the generator aborts on any pin drift and never
rewrites the copied bytes.

- Affected: `gpfdist.c:3846-3847` (is_final/seq reset), `:3864` (count),
  `:3866` (id), `:3893` (seq), `:1975`/`:1978` (two zeroed arrays sized by
  `r->totalsegs`), `:1988` (`active_segids[r->segid] = 1`), `:1989`
  (`maxsegs = r->totalsegs`), `:2038` (`active_segids[r->segid] = !r->is_final`),
  `:3677` (`seq_segs[r->segid] = r->seq`).
- Fixed: `gpfdist.c:407` (`GPFDIST_MAX_SEGMENTS 32767`), `:1865-1871`
  (create-time count/id guard), `:1998-2001` (same two allocations),
  `:2011-2012`, `:2063-2068` (join-time id guard), `:2074`, `:3713`.

Harness stand-ins, all outside the copied statements: `pcalloc_safe` becomes
`calloc(1, n)` for exact allocations or a zeroed 1 MiB `mmap` collaborator for
layout control; `http_error`/`request_end` are no-ops so the pinned `return -1`
in each fix guard remains observable; a fake 3-header `request_t` feeds the
verbatim `atoi`/`atol` parse lines. No live process, HTTP server, APR pool
layout, real neighbour object or stock allocator is exercised.

## Harness digests and replay

- `gen_driver.py` `092a80ec9f1b899b072ee93c715e451689f6fb21c8fa320ebc6c17146aa0c77c`
- `run.sh` `7d96799edee7a861ef01995263c8def7edefa7640a1cfc51a9ba57d973f19a22`
- Generated `driver_vuln.c`
  `0b1264aa98bbd17fda577445647d2de0057debd8be79ca9535fd8f3078bcbe39`
- Generated `driver_fixed.c`
  `9fa24fdd619b4e6fc844c956f2266689c20be1f1ae8869e8d5f11d472f02c6c6`
- `bash lab/frontier/gpfdist2shell/run.sh <outdir>`: **13 PASS / 0 FAIL,
  ALL CHECKS PASS rc 0**; two independent five-run groups both
  `sha256=4f8bf8b7c6de06df7ce370b3570babe8df25112b9d2380c9836852864a8048c4`.

ASan reports are checked for fixed marker text only; PIDs, addresses and build
paths are excluded from the trace digest so clean replays are byte-identical.
