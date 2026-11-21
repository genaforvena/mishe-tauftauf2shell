# Provenance — rtp2httpd interleaved-frame overflow harness

All bytes below were fetched read-only from public GitHub endpoints on
2026-11-21 (provisioning, not probing). No rtp2httpd daemon was built, run or
contacted; the harness is an extracted C driver with stand-in types and a
controlled mmap/heap arena. Loopback and external targets were never probed.

## Upstream pins (SHA-256 of the exact bytes stored in `src/`)

| File | SHA-256 | Source |
|---|---|---|
| `rtsp.v3.14.1.c` | `96eb3b4a37ad893a4c4567372c3c415c32e49eb3c60552009d841c34ce999415` | `https://raw.githubusercontent.com/stackia/rtp2httpd/v3.14.1/src/rtsp.c` |
| `rtsp.v3.14.2.c` | `b355f4afec1d66ba08caf02a77093860996f02d822f8308b1bf35509793fbe19` | `https://raw.githubusercontent.com/stackia/rtp2httpd/v3.14.2/src/rtsp.c` |
| `rtsp.v3.14.1.h` | `c3604cf570ba816edbb8adb41409e35f997cf877319ebbad4110897d34c91997` | `https://raw.githubusercontent.com/stackia/rtp2httpd/v3.14.1/src/rtsp.h` |
| `buffer_pool.v3.14.1.h` | `8c8632ce61d5bf5f15f00b0c5a31b1a73433a8a5bcc1107f821f8e1110e3d6ea` | `https://raw.githubusercontent.com/stackia/rtp2httpd/v3.14.1/src/buffer_pool.h` |
| `buffer_pool.v3.14.1.c` | `30f5758d0b9d04eecb23c4553663f049718f997b77ade298e694e014be13612b` | `https://raw.githubusercontent.com/stackia/rtp2httpd/v3.14.1/src/buffer_pool.c` |
| `zerocopy.v3.14.1.c` | `8d8b0eb09dc6ce307945579db9f0eb1c03db7db600ce03c5e9e172c538f91dc5` | `https://raw.githubusercontent.com/stackia/rtp2httpd/v3.14.1/src/zerocopy.c` |
| `fix353.patch` | `85c05de446e2efa148a96c3390c12c82e9c937d45c374e2e89dc4ad7b99769a6` | `https://github.com/stackia/rtp2httpd/commit/f0fcfc194631e13266cbcfcc1818dde24932978a.patch` |
| `advisory353.json` | `eb55aed5e5e7805e0c34d40d89dac82a9234f56b4448a35073497edd017e6fba` | `https://api.github.com/repos/stackia/rtp2httpd/security-advisories/GHSA-35fv-hf3m-2pqc` |

`gen_driver.py` recomputes all eight SHA-256 values and exits 3 on any drift
before it writes a driver (`pins: all 8 SHA-256 match` on a clean replay).

Upstream git blob SHA-1 pins (from the GitHub commit API, read-only): vulnerable
`src/rtsp.c` blob `2374c34e8f59e68a756de3ce2b1e0c6f12f68697`; fix post-image
blob `4e9a111df34d8a08fe302f59aae742d57919dc3b`, commit
`f0fcfc194631e13266cbcfcc1818dde24932978a` (parent
`959a5d34d533ea64bd021d95356d6b2113b67c87`), verified GPG-signed and an
ancestor of `v3.14.2` (compare: ahead 4, behind 0).

## Claim source

GHSA-35fv-hf3m-2pqc, publisher `stackia`, published 2026-06-27T08:33:58Z,
updated 2026-06-27T17:59:44Z. No CVE assigned (`cve_id: null`). Severity
critical, CVSS 3.1 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` score 9.8. CWE-122,
CWE-131, CWE-787. Vulnerable range `<= 3.14.1`; fix commit in `v3.14.2`.
The advisory claims remote DoS and *potential* RCE; execution is not
demonstrated by the advisory, nor by this harness.

## Source-bound statements copied verbatim by `gen_driver.py`

`copied()` reads the exact pinned line ranges and emits them under `#line`
markers at their true source line numbers; scaffolding is reset to
`#line 900 "driver.c"`. Independent comparison found 28 copied lines in each
driver, zero mismatches against the pins.

- Vulnerable `rtsp.v3.14.1.c`: `:1791-1792` (channel and 16-bit BE wire length),
  `:1795-1797` (completeness check), `:1799-1816` (guard against
  `RTSP_RESPONSE_BUFFER_SIZE - 4` = 4092, plus resync/break), `:1822-1826`
  (channel match, `buffer_pool_alloc()`, `memcpy` at `:1825`, `data_size`).
- Fixed `rtsp.v3.14.2.c`: `:1792-1793`, `:1796-1798`, `:1800-1817` (guard
  changed to `BUFFER_POOL_BUFFER_SIZE` = 1536), `:1823-1827` (the identical
  `memcpy` now at `:1826`).

Sizes are source-bound: `rtsp.v3.14.1.h:25` `RTSP_RESPONSE_BUFFER_SIZE 4096`;
`buffer_pool.v3.14.1.h:13` `BUFFER_POOL_BUFFER_SIZE 1536`; `buffer_pool.c:58`
`posix_memalign(buffer_size * num_buffers)` and `:73`
`ref->data = segment->buffers + i * 1536`; `zerocopy.c:97` initializes the pool
with `BUFFER_POOL_BUFFER_SIZE`. Maximum overshoot is `4092 - 1536 = 2556`
chosen bytes.

## Harness stand-ins (not upstream code)

`buffer_pool_alloc()` returns a `buffer_ref_t` whose `data` is either a
1536-byte `malloc` (`exact` mode, for ASan) or a slot inside a 4-page mmap with
the last page `PROT_NONE` (`collab`/`guard` modes). In `guard` mode the slot
ends exactly at the guard page so the first past-end store faults. `logger`,
`LOG_ERROR`, `LOG_DEBUG`, `connection_t`, `stream_t` and the session struct are
scaffolding. Source bytes are a repeating four-byte seed at `response_buffer[4]`.
No stock allocator neighbour, live pool metadata, pointer control or execution
is claimed.

## Observed result (author replay, 2026-11-21)

`bash lab/frontier/rtp2httpd2shell/run.sh <outdir>` from committed HEAD:
10 PASS / 0 FAIL rc 0. Two independent five-run groups both
`sha256=11a76ab0bcb678868229982cb64a826f0367f29d8c4b3daf9eb84eb5804ceb13`.
ASan: heap-buffer-overflow `WRITE of size 4092`, 0 bytes after a 1536-byte
region, framed at the verbatim `rtsp_v3.14.1:1825`. Guard mode faults with
rc 139. Fixed build rejects length 4092 and accepts 1536; both ASan-clean.
