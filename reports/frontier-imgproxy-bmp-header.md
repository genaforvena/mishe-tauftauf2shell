# Frontier brief — imgproxy ICO BMP-header reconstruction (CVE-2026-123615) — SCREENED OUT

**Status (2026-11-21): SCREENED OUT. No harness, no window, no rung claimed.**
This is a real, distinct CVE, but its OOB write is not a chosen-value write and
its demonstrated impact is availability only. It also shares the file,
function and HTTP path with the already-admitted Imgproxy2Shell target
(CVE-2026-123614, window 48), so a second harness/window would duplicate that
lane. Recorded here to preserve the negative result and the decisive
source-bound reason, not to advertise a candidate.

## Verified ground truth (read-only provisioning, 2026-11-21)

- **Advisory**: CVE-2026-123615 / GHSA-494m-4556-wf5p / GO-2026-6895; CNA
  VulnCheck. Reserved `2026-11-06T01:04:42Z`, published
  `2026-11-08T01:38:39.703Z`; CVELIST updated `2026-11-13T03:13:20Z`; GHSA
  originally published 2026-10-06 by DarthSim. Credit: haileyok.
  Sources: <https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/123xxx/CVE-2026-123615.json>,
  <https://api.osv.dev/v1/vulns/CVE-2026-123615>,
  <https://github.com/imgproxy/imgproxy/security/advisories/GHSA-494m-4556-wf5p>,
  <https://www.vulncheck.com/advisories/imgproxy-before-4.0.17-out-of-bounds-write-in-ico-loader>.
- **Scores / CWE**: CVSS 4.0 `AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N`
  = 8.7 HIGH; CVSS 3.1 7.5 HIGH. CWE-787 in the CVE record, CWE-125 also in
  the GHSA. CISA SSVC: exploitation `poc`, automatable `yes`, technical impact
  `partial`. Both records describe a worker crash, not code execution.
- **Primitive prose (verbatim from the CVE)**: "out-of-bounds heap read and
  write in the ICO loader's BMP header reconstruction ... when an ICO entry
  declares a tiny data size, causing unvalidated header fields to be read and
  written past the allocated buffer ... corrupting adjacent heap chunk
  metadata, triggering a glibc abort that crashes the worker." GHSA: "The
  corrupted size is always `original_size >> 1`" and "demonstrated impact is
  denial of service".
- **Affected/fixed**: `>=3.3.0` to `<4.0.17` (OSV enumerates v3.3.0–v4.0.16).
  OSV's `fixed` commit `2c89e4ebff3384caf6752db2ec861b4ef5fe675c` is only a
  version bump. The real code fix is
  `39fd9e844a8a46084161502e993d5a3c16ccf28d` ("fix: ICO BMP payload size
  check to prevent out-of-bounds reads on truncated headers", 2026-09-29/30),
  a one-line guard change plus `testdata/ico-bad4.ico` and a Go test:
  <https://github.com/imgproxy/imgproxy/commit/39fd9e844a8a46084161502e993d5a3c16ccf28d.patch>.
- **Pinned raw bytes already in the plant**: `src/icoload.v4.0.15.c` SHA-256
  `2eabd58d1e6c14439af7a7e22196df2ea4f4b2aa82efeb1ea0844962744051dc` and
  `src/icoload.v4.0.16.c` SHA-256
  `67b4a9c2667743ac757faa59e1f56dc09ed8046dc5efd8c74a24c0f41e795774` live in
  `lab/frontier/imgproxy2shell/` and are re-verified by that harness on every
  run. v4.0.17 raw bytes and the published PoC's SHA-256 were **not**
  independently recomputed here (UNKNOWN).

## Source-bound mechanism and the decisive negative

Line numbers are from raw tag `v4.0.15` `vips/icoload.c`, observed directly:

1. `:160` reads the attacker-declared `uint32_t data_size` from the ICO
   directory entry; `:164` allocates exactly `data_size + BMP_FILE_HEADER_LEN`
   (14) bytes; `:165` sets `actual_data = data + 14`; `:167` copies `data_size`
   payload bytes to `actual_data`.
2. `:193` reads `num_colors` at `actual_data + 32` and `:194` reads `bpp` at
   `actual_data + 14`; both are OOB reads for small `data_size`. These feed
   `pix_offset`, written at `:219` to `data + 10` — always inside the minimum
   14-byte allocation, even though its *value* is attacker-influenced.
3. `:209` reads `height` from `actual_data + 8` (= `data + 22`), `:210` halves
   it, and `:220` writes it back to the **same address** `actual_data + 8`.
4. The `:220` store crosses the allocation iff `data_size + 14 < 26`, i.e.
   `data_size < 12`. But the `:209` load uses the identical address, so on
   every OOB write the load is OOB too: the stored value is an adjacent heap
   word divided by two, **not an attacker-chosen word**. There is no
   `data_size` for which the load is in bounds and the store out of bounds.
   `:217`'s `data_size + 14` store at `data + 2` and `:219`'s `pix_offset`
   store at `data + 10` are likewise always in bounds.
5. Consequence: the only attacker-controlled parameter is the *offset*
   (through allocation size); the value is heap-derived. This corrupts the
   next chunk's size field and aborts glibc — an availability primitive, not
   the chosen-byte / pointer-control impact this plant calls rung 4.

Version overlap confirms the lane duplication: v4.0.16 added
`if (full_data_size < BMP_BITMAP_INFO_HEADER_LEN)` (40), i.e. it rejects
`data_size < 26`, so the published tiny-size PoC is rejected there; a residual
OOB **read** remains for `data_size` 26–35. The v4.0.17 fix changes the test to
`if (data_size < BMP_BITMAP_INFO_HEADER_LEN)` (40). Both CVEs live in this one
`vips_foreign_load_ico_header()` function and are reached over the same
unauthenticated `/insecure/plain/...` source-URL path; CVE-2026-123614's fix
(`a821b6a4`) already masked part of this bug in the admitted target's lane.

## Cheapest experiment if this is ever revisited

Build imgproxy at `v4.0.15` with vendored libvips under ASan on 127.0.0.1,
feed a tiny-`data_size` ICO, and expect a heap-buffer-overflow read at pinned
`:193` and write at `:220`, plus the reported `munmap_chunk(): invalid pointer`
abort; confirm v4.0.16 rejects `data_size < 26`. That would establish rungs 2/3
only. Nothing in the raw lines supports promoting it to rung 4 without a
different, attacker-controlled write value. Not scheduled.

## Scope

Advisory and source fetches were read-only provisioning. No imgproxy build,
no ICO trigger, no HTTP request and no external probe was performed; the
mechanism above is source-bound, and live heap layout/PoC hash are UNKNOWN.
