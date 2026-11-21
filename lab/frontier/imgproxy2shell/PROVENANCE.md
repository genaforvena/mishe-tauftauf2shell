# PROVENANCE — Imgproxy2Shell (CVE-2026-123614)

All sources below were fetched read-only from public origins on 2026-11-21;
nothing outside loopback was probed or contacted with a trigger.

## Upstream pins (SHA-256 of the exact bytes stored in `src/`)

| Artifact | Origin | SHA-256 |
| --- | --- | --- |
| `src/icoload.v4.0.15.c` (affected) | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.15/vips/icoload.c` | `2eabd58d1e6c14439af7a7e22196df2ea4f4b2aa82efeb1ea0844962744051dc` |
| `src/icoload.v4.0.16.c` (fixed) | `https://raw.githubusercontent.com/imgproxy/imgproxy/v4.0.16/vips/icoload.c` | `67b4a9c2667743ac757faa59e1f56dc09ed8046dc5efd8c74a24c0f41e795774` |
| `src/fix123614.patch` (upstream fix commit) | `https://github.com/imgproxy/imgproxy/commit/a821b6a4cb07a1bf2bb9077431d1c1e734d79917.patch` | `c5db17e90ab1b9ad103a9a1e2a36d1a6ecd894dd816b79997f57049b136e00b0` |
| `src/advisory123614.html` (GHSA-hff9-5pqw-6w9f) | `https://github.com/imgproxy/imgproxy/security/advisories/GHSA-hff9-5pqw-6w9f` | `d6de60b26ceb5946dda041617a27159f15316791458098c0fbac14b34d5f0e0e` |
| `src/cve123614.json` (CVE Program record) | `https://cveawg.mitre.org/api/cve/CVE-2026-123614` | `ab297c9dda361812ee88996649833b78b9ce7c7fc5d5e1c4c7c297d65c027dc1` |

Fix commit `a821b6a4cb07a1bf2bb9077431d1c1e734d79917` is dated
2026-09-24T17:27:35+03:00 with subject "Fix segfaults during invalid ICO
load"; it adds `MAX_ICO_ENTRY_DATA_SIZE` (10 MiB) and an explicit
`full_data_size` variable, plus regression ICO files and Go tests.

CVE-2026-123614 was published 2026-11-08 by GitHub's CNA, CWE-122,
CVSS 4.0 9.3 Critical `AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`,
CVSS 3.1 9.8. Affected `imgproxy` package `pkg:golang/github.com/imgproxy/imgproxy/v4`
from 4.0.0 before 4.0.16; 4.0.16 is unaffected. CVE prose claims heap
corruption, crash or code execution from a crafted `data_size`.

## Source-bound statements copied verbatim by `gen_driver.py`

The generator emits only the loader statements under `#line` markers at their
true line numbers and aborts on any pin drift.

- Affected `icoload.c:154` — `uint32_t data_size` from the ICO directory
  entry; `:158` — `VIPS_MALLOC(NULL, data_size + BMP_FILE_HEADER_LEN)` (14-byte
  allowance, `uint32_t` addition wraps); `:159` — `actual_data = data + 14`;
  `:161` — `vips_foreign_load_read_full(ico->source, actual_data, data_size)`.
- Fixed `icoload.c:162`, `:165-168` — reject `data_size > 10 MiB`; `:172-173`
  — compute `full_data_size` in a 32-bit variable after the guard and allocate
  exactly that; `:179`, `:181` — same read path into the sized buffer.

Harness stand-ins, all outside the copied statements: `VipsPel` is
`unsigned char`, `VIPS_MALLOC` routes to a stand-in returning an exact-size
allocation (ASan mode), a zeroed 1 MiB mmap collaborator at a known offset
(chosen-byte readback), or a 3-byte allocation at the end of a `PROT_NONE`
guard page (fault control); `vips_foreign_load_read_full` copies at most the
locally supplied body bytes to `actual_data`, modelling a short source;
`vips_error` is a no-op. No imgproxy HTTP server, libvips runtime or real ICO
network request is exercised.

## Harness digests and replay

- `gen_driver.py` `f379809cbff319cc56577cffb0c73449c8c9736ef6c30c18242d6edc9db2d5bb`
- `run.sh` `51e7b46cf3e7cf62094e0f7ac83cf6ed1590d6de915de18ccc4e056458ed2c51`
- Generated `driver_vuln.c`
  `874d5784102ad8d5f5e987a2e0db96f3dc220968ea0a9dfa813d016dabededba`
- Generated `driver_fixed.c`
  `7214cf9ecc704dfb1022d630de8f83681b77643f7c723398203f225054528834`
- `bash lab/frontier/imgproxy2shell/run.sh <outdir>`: **10 PASS / 0 FAIL,
  ALL CHECKS PASS rc 0**; two independent five-run groups both
  `sha256=6b0391599520bc899f169268e08699155888f0018274f9c2a2e12bcd31c2dad5`.

Clean replay from `git archive HEAD` is recorded in the frontier brief once
performed; ASan PIDs, addresses and build paths are excluded from the digest.
