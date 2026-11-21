# Provenance — accelppp2Shell

All bytes were fetched read-only from upstream GitHub (provisioning, not
probing). No external system was contacted with exploit input.

## Advisory ground truth

- CVE-2026-123205, CNA VulnCheck, published 2026-11-05, CWE-122,
  CVSS 4.0 8.3 `AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:L/VA:H/SC:N/SI:N/SA:N`.
  Range `>= 0, < 1.15.0`; affected versions listed 1.10.0/1.12.0/1.13.0/
  1.14.0. Claim: unauthenticated peers inside client-ip-range send an L2TP
  Start-Control-Connection-Request with many string AVPs while verbose logging
  is enabled; tcp/syslog/pgsql log targets copy chunk lists into fixed buffers.
- OSV: https://api.osv.dev/v1/vulns/CVE-2026-123205
- VulnCheck advisory: https://www.vulncheck.com/advisories/accel-ppp-before-1.15.0-heap-based-buffer-overflow-via-oversized-log-lines-in-log-tcp-log-syslog-log-pgsql
- Fix commit: `58e399400c4ef4b71472ab7c2c71c54a677a05a8`
  ("log: bound log lines and share target unpacking", 2026-10-28).
- PR: https://github.com/accel-ppp/accel-ppp/pull/374
- Release: https://github.com/accel-ppp/accel-ppp/releases/tag/1.15.0

## Pinned files and SHA-256

Fetched from `https://raw.githubusercontent.com/accel-ppp/accel-ppp/<tag>/<path>`
into `src/`:

| file | 1.14.0 (affected) | 1.15.0 (fixed) |
|---|---|---|
| `accel-pppd/log.c` | `2ddbf3ffc5a942ccfd4c13f560209d6b3880aa82ebe2b0e69e763595b9da1ef0` | `f105aeed510b8a7699606337d10e067af06b7b12d03e20d931d1260c4474e6f7` |
| `accel-pppd/log.h` | `022d9890a579b15aad5d8d68349d364673d2a874ac4908f09494aea5c2a3a0b4` | `eff7bd26bba2d1ac7a4fb4a78aa56cc287ecf2f343e0b5b1ee7b8180e05d19b1` |
| `accel-pppd/logs/log_tcp.c` | `449eb3ef08cc09176b0dfeb24170288fbcf738e8ff247ce25a4b8076fd78f7d7` | `f21a1191f87d6c38079eafac199edb96c29f6592fa33f9934f6cf6f9e94124b7` |
| `accel-pppd/logs/log_syslog.c` | `674023ce56784bae5c24c9f374f21372e98348f8f9bed73aa75fa78ac04404f7` | `044c7abacc18990983cac9a8b12ad22be248558d186102dd0312cf28719e563e` |
| `accel-pppd/logs/log_pgsql.c` | `7c6e8d85802ce4033ac05abf777e2202a93ce0cddb5107757d516df67102f88a` | `6bab117571c30261c991f1757b76a8990a74c87630ab1793702b2bb0d706315f` |

Fix patch: `src/fix-58e3994.patch`,
SHA-256 `02c2ff3a9306203d1d72365b5c907d3f4a5faf0e0944e59304fcb9b3404f32c4`,
fetched from `https://github.com/accel-ppp/accel-ppp/commit/58e399400c4ef4b71472ab7c2c71c54a677a05a8.patch`.

`log.h:8` pins `LOG_MAX_SIZE 4096`; vulnerable `log_tcp.c:269` allocates
`LOG_MAX_SIZE + 64` = 4160 bytes; vulnerable `log_tcp.c:55-69` is the
extracted function (unchecked `memcpy` at line 63). Fixed `log_tcp.c:57-66`
calls `log_unpack_msg()` extracted from `log.c:295-309`.

## Replay

`bash lab/frontier/accelppp2shell/run.sh <outdir>` verifies all hashes,
extracts the verbatim functions with leading-line padding so upstream line
numbers survive, compiles three modes with gcc 13.3.0 `-O0 -g`, and asserts
19 checks. Clean replays: 19 PASS, `ALL CHECKS PASS rc 0`, trace SHA-256
`3499f52eef8814e5cc73c5e38f990ca0de3f4f0fc243640452c7806dc9c2b18a`
(three byte-identical runs, plus a relative-outdir run, all identical).
