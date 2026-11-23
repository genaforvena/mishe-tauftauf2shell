# Provenance — thrift2shell harness (W143, 2026-11-23)

CVE-2026-55971 / GHSA-gwj4-q93m-wwqc, Apache Thrift C++ `untransform()` ZLIB
heap write overflow. All provisioning was read-only fetching of public upstream
blobs and advisory pages; no external host was probed. The harness runs only
inside this directory with a direct function call: no daemon, socket, listener,
TLS, Thrift process, protocol exchange or network.

## Pinned inputs

Hashes are the exact bytes checked by `src/SHA256SUMS` (9 files) and
`harness/SHA256SUMS` (15 files) on every run.

| File | SHA-256 | Origin |
|---|---|---|
| `src/THeaderTransport.cpp.v0.23.0` | `b2c85baefb0db672b40e80ecb493f7f78757c22ffd97e1608e9e200871e7737c` | `raw.githubusercontent.com/apache/thrift/v0.23.0/lib/cpp/src/thrift/transport/THeaderTransport.cpp` (vulnerable release) |
| `src/THeaderTransport.cpp.parent` | `c5d92829750840164879cb674aaefa43014f65dd96ee792fbd75c5ecca9d513a` | `git show db4a473f3a984eee27273256fe737be5dd175595^:lib/cpp/src/thrift/transport/THeaderTransport.cpp` (fix preimage; blob prefix `cdf29cf3d53` matches patch index) |
| `src/THeaderTransport.cpp.fix` | `ddcb785f22f53b7b805e8c52aae217e1c76d0c141b497f456934ecf6d74c3941` | `git show db4a473f3a984eee27273256fe737be5dd175595:lib/cpp/src/thrift/transport/THeaderTransport.cpp` (fix postimage; blob prefix `891059b888e` matches patch index) |
| `src/THeaderTransport.cpp.v0.24.0` | `d3e62f54187bf9791b64ccddab87142db7736cc6a7ba99bfcc680056ec3667aa` | `raw.githubusercontent.com/apache/thrift/v0.24.0/lib/cpp/src/thrift/transport/THeaderTransport.cpp` (patched release) |
| `src/THeaderTransport.h.v0.23.0` | `7a854d06e9515ce88f4fe755d0b3dd8e104ee0b532518e9c01fb68cfe1ac2dbc` | `raw.githubusercontent.com/apache/thrift/v0.23.0/lib/cpp/src/thrift/transport/THeaderTransport.h` (constants: `DEFAULT_BUFFER_SIZE=512u` :71, `ZLIB_TRANSFORM=0x01` :168) |
| `src/fix-db4a473f.patch` | `116d041159aa9aa4191d64ee7088fd8a80c854cb703bb17d05062ddd9ba7f869` | `github.com/apache/thrift/commit/db4a473f3a984eee27273256fe737be5dd175595.patch` |
| `src/GHSA-gwj4-q93m-wwqc.html` | `22c6b3c07f64d7ba1f00d0e16eb9b3d568507937e27b23069a26897e2a551271` | `github.com/advisories/GHSA-gwj4-q93m-wwqc` |
| `src/vendor-advisory-2026-07-24.html` | `80d76549592560954a2a6f4e0ac67d590dcccc62887dfdb654ba8811d3a14bf2` | oss-security post, CVE-2026-55971, subject "C++ ZLIB heap buffer overflow (write) in THeaderTransport::untransform()" |
| `src/CVE-2026-55971.html` | `3c1e35d4d223526265b290fa526d4a2432ecde0a85de5a3e7f785d626ed6d4d5` | `cve.org/CVERecord?id=CVE-2026-55971` — captured page is an 880-byte JavaScript SPA shell with **no advisory text**; not used as a claim source |

GHSA body: Critical 9.3,
`CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, CWE-122,
"affects Apache Thrift: before 0.24.0", "upgrade to version 0.24.0". Its
metadata fields ("Affected versions: Unknown", "Patched versions: Unknown",
"No package listed", "Unreviewed") are stale and contradict its own body;
the oss-security post and the two release blobs agree with the body. The
tag mapping is by pinned filename and `run.sh` label, not an embedded version
string. No pinned advisory claims code execution or a shell.

`run.sh` also verifies the fix patch's preimage/postimage git blob identities
(`git hash-object` prefixes `cdf29cf3d53` / `891059b888e`), so a swapped or
edited blob cannot pass silently.

## Verbatim slices re-extracted per run by `harness/run.sh`

| Slice | Vulnerable source | Fixed source |
|---|---|---|
| `vuln/untransform.inc` | `THeaderTransport.cpp.v0.23.0:263-308` | — |
| `rel023/untransform.inc` | `THeaderTransport.cpp.parent:282-327` | — |
| `fix/untransform.inc` | — | `THeaderTransport.cpp.fix:282-333` |
| `rel024/untransform.inc` | — | `THeaderTransport.cpp.v0.24.0:286-337` |

Each slice is the **complete upstream `untransform()` function**, re-created
with an `echo '#line N "THeaderTransport.cpp.<pin>"'` header followed by `sed
-n 'N,Mp'` of the pinned blob, so ASan and gdb attribute the fault to the pinned
line rather than the generated file. Rendered line numbers are claims; raw
pinned bytes rule. Only the function's object environment is stubbed
(`TApplicationException`, `Buf`, `THeaderTransport`, `resizeTransformBuffer`,
`setReadBuffer`).

## Harness inputs and stubs

`driver.cpp` compresses a payload of 700 identical `0x42` bytes (the size used
by the upstream regression test added in the fix patch) to 31 bytes with zlib,
then models the real reader: `rBuf_` is a 31-byte heap frame buffer sized from
the compressed length, `tBuf_` is a 1024-byte transform buffer
(`wBufSize_=512` + `DEFAULT_BUFFER_SIZE=512`, mirrored from pinned
`THeaderTransport.cpp.v0.23.0:317-324`). Chosen marker bytes
(`41/5a/7a/3c/7b/42/7b`) are placed in the payload at offsets 0/16/32/64/128/
256/699. The adjacent 4096-byte `0xCC` sink exists only to observe the smear
after the write in plain builds. Modes: `attack` (700 bytes), `safe` (4 bytes,
in bounds in all variants), `oversize` (4096 bytes, rejected by the existing
`avail_out == 0` gate before any copy), `arith` (no call).

Variants: vulnerable v0.23.0 and fix parent (copy back), fix commit and
released v0.24.0 (swap buffers). ASan builds use gcc and clang; gdb observes
chosen bytes at the pinned `memcpy` line in the vulnerable build and the swap
line in the fixed build. `set -u`, no `set -e` — failures are counted by the
`ok`/`no` helpers and the runner exits nonzero on any `FAIL`.

The normalized trace strips PID, absolute paths, build IDs, addresses and
frame numbers; its SHA-256 is the replay digest. No harness byte is a pointer,
gadget, ROP chain or command.

## Replay record

- Three consecutive local runs and a clean-`/tmp` run: `PASS=71 FAIL=0`,
  trace `c12ba2145cec292e618d2f50677887c61a56d577b012577cd50c304731bbe556`
  (2026-11-23 W143).
- No external host was contacted during replay; the harness opens no socket.
