# open5gs2shell provenance

All provisioning was read-only public fetching; no external target was
probed. Every pinned file and the fix patch are hashed in `pins.sha256` and
rechecked by `harness/run.sh` PASS-21.

- Vulnerable tag `v2.8.0` (`https://github.com/open5gs/open5gs/tree/v2.8.0`):
  - `provision/multipart_parser-v2.8.0.c` — `lib/sbi/contrib/multipart_parser.c`,
    raw URL `https://raw.githubusercontent.com/open5gs/open5gs/v2.8.0/lib/sbi/contrib/multipart_parser.c`,
    SHA-256 `dd49438c0792b6746b3b7eddd2820f1b17d06db5c68ff8a656931556f39da092`.
  - `provision/multipart_parser-v2.8.0.h` — same path with `.h`, SHA-256
    `edb354d9f4d9d0fbc5569bf2bddd9a2b6221d09026cf949a186eb6df8d08d165`.
    Byte-identical copy at `harness/multipart_parser.h` for include resolution.
  - `provision/message-v2.8.0.c` — `lib/sbi/message.c`, SHA-256
    `a9678094c367e10c6ef4213b645ef23d55986616ad4ffd0af96e021687fcf64d`.
    The advisory's `parse_multipart` line numbers refer to a later tip
    (patch hunk at :3507); this pinned v2.8.0 copy has it at :3324. The
    parser sink file is pinned separately and compiled verbatim.
- Fix: `https://github.com/open5gs/open5gs/commit/6820c2743b5b5e126e3755d2f92dae2b236732df.patch`
  saved verbatim as `provision/fix-6820c274.patch`, SHA-256
  `a94237e1ba60c28b10347f18ca07164264e48b566c7c650ddb833a49e3c75ba3`.
  Its six-line empty-boundary guard is reproduced in
  `harness/harness.c` under `#ifdef FIXED_BUILD`.
- Claim sources: VulnCheck CVE-2026-116543 advisory (2026-10-26) and
  Open5GS GHSA-25v2-v588-jq8g (2026-09-25), both read-only.

## Harness scope

`provision/multipart_parser-v2.8.0.c` is compiled **unmodified**; the only
substitutions are `harness/ogs-core.h` stand-ins for `ogs_error`, `ogs_free`,
`OGS_ERROR` and `OGS_GNUC_FALLTHROUGH`. `harness/harness.c` supplies
zero-returning callbacks, the pinned-field-shaped request body and the
guard. No parser logic is reimplemented. Report line numbers are claims
about pinned bytes; SHA-256 pins are authoritative.

## Harness evidence

`sh harness/run.sh`: 21 PASS / 0 FAIL, rc 0.

- `harness/evidence/asan-vuln-attack.out`: `WRITE of size 1`, `0 bytes after
  65-byte region`, `multipart_parser-v2.8.0.c:260`, allocation at :82.
- `harness/evidence/plain-vuln-attack.out`: canary
  `5a5a…` → `0a000d0a000d0a000d0a000d`; `RET=394 LEN=394`.
- `harness/evidence/asan-vuln-safe.out`, `asan-fixed-attack.out`,
  `plain-vuln-safe.out`, `plain-fixed-attack.out`: clean; fixed returns -1.
