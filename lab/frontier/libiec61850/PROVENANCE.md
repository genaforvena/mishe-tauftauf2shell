# Provenance — libIEC61850 CVE-2026-49035 harness

Fetched read-only on 2026-11-21 ~13:40–13:42Z from the named public endpoints
(provisioning only; every packet in the harness goes to 127.0.0.1). SHA-256
digests are in `src/SHA256SUMS` and checked by `run.sh` before any build.

| Pin | Source |
| --- | --- |
| `cve-cve-2026-49035.json` | `https://cveawg.mitre.org/api/cve/CVE-2026-49035` |
| `nvd-cve-2026-49035.json` | `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2026-49035` |
| `fix-db35acf6.json` | `https://api.github.com/repos/mz-automation/libiec61850/commits/db35acf67bfdb4c5bdbcfb19b66529476bf72d21` |
| `libiec61850-a1396111.tar.gz` | `https://codeload.github.com/mz-automation/libiec61850/tar.gz/a13961110b8238d2d8ea577c1fb7592ba3017ad8` |
| `libiec61850-v1.6.2.tar.gz` | `https://codeload.github.com/mz-automation/libiec61850/tar.gz/refs/tags/v1.6.2` |
| `libiec-security-poc-main.tar.gz` | `https://codeload.github.com/abhinavagarwal07/libiec-security-poc/tar.gz/refs/heads/main` |

The CISA advisory page returned HTTP 403 to provisioning; its claims here come
from the pinned CNA/NVD records and the vendor fix commit. The GitHub `.patch`
endpoint returned 503, so the fix hunk is pinned as the commit API JSON.

## Verbatim / third-party components

- Both library tarballs are extracted and compiled verbatim with explicit
  `-fsanitize=address -g -O0 -fno-omit-frame-pointer`; the CMake option
  `WITH_ADDRESS_SANITIZER=ON` is ignored by this upstream and is **not** used.
  Neither source tree is edited.
- The raw MMS packet client
  `CVE-2026-49035-mms-fileread-heap-rce/poc/raw/exploit_raw.py` comes verbatim
  from the pinned public PoC tarball (GPL-3.0-or-later, © 2026 Abhinav
  Agarwal). It is invoked as an external tool; no PoC code is copied into the
  harness. Its self-reported "Server CRASH" line is a client inference and is
  checked against the server's own ASan report.
- `run.sh` is harness-authored. It stages a 200000-byte local VMD filestore
  file of alternating chosen `0x5a`/`0xa5` bytes and a 200-byte small-file
  control, then starts the stock ASan `server_example_files` binary on
  unprivileged loopback ports and stops it after each case.

## Labels and limits

- ESTABLISHED here: unauthenticated loopback MMS Initiate + FileRead drives a
  real ASan `WRITE of size 178157` in the pinned library's
  `mms_file_service.c:872`, 0 bytes past the 65100-byte `sendBuffer` allocated
  at `iso_connection.c:516`. Legal PDU size and small-file controls are clean.
- Frontier's original file bytes were chosen locally; see
  `reports/iec618502shell-r4.md` for the later rung-4 probe. That probe uses
  the pinned ObtainFile client with a benign ramp (remote byte choice,
  SHA-256 matched) and gdb to observe those bytes at chosen offsets past
  `sendBuffer` and in a live pointer field. Rung 4 is reached at the
  chosen-byte-write boundary only: pointer control, wire readback,
  control-flow diversion and execution remain UNKNOWN. The public RCE chain
  needs ASLR-off/non-PIE/AArch64 offsets and was not run.
- **Fixed-side negative result**: released v1.6.2 contains the min-PDU guard
  (`mms_association_service.c:346`, commit `db35acf6`) and does reject the
  Initiate, but it stores the bad `maxPduSize` *before* rejecting and the raw
  client reuses the association; the later FileRead still overflows under
  ASan. That is an observation about this route, not proof that all clients
  can bypass the fix; a conforming client would stop on the AARE failure.
  That conforming-client behavior is now verified by `r4_probe.sh` on the
  fixed ASan build (connect failure, no FileRead, no ASan report).

## Replay

`bash run.sh <absolute-outdir>` prints pins, builds, ASan/control checks and
`TOTAL PASS=7 FAIL=0`, with two three-run groups of path/PID/address-normalized
ASan signatures.
