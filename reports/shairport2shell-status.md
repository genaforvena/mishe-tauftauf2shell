# shairport2shell — status

Frontier find handed off 2026-11-21 ~03:36Z; not yet admitted by the operator.
Advisory: GHSA-6g79-wrcj-h8xw (maintainer, 2026-09-04), High 7.5,
`AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H`, CWE-121, no CVE assigned. Affected
`< 5.5`; patched `5.5` and `5.6-dev`. Claim: pre-auth RTSP unrecognised-method
hex dump writes up to 8193 bytes into `char obf[4096]` on AirPlay-2 builds.
Brief: [frontier-shairport2shell.md](frontier-shairport2shell.md). Pins, raw
URLs and hashes: `lab/frontier/shairport2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/shairport2shell/run.sh <outdir>` — 21 PASS,
  `ALL CHECKS PASS rc 0`, trace SHA-256
  `b87176f5891ef547eef69a11176fd3e0a3a3c367fd19fdf80d30fa9b733e9c86`.
  Verified from a clean `git archive HEAD` extraction and from two separate
  output directories (byte-identical trace).
- Rungs 1/2/3 on verbatim pinned upstream `rtsp.c:4206-4221` from fix parent
  `a50f184` (affected) and fix `c1c41c4`: a 4096-byte body writes 8193 bytes
  into `obf[4096]` (4097 bytes past); harness neighbour `first_changed=0`;
  ASan `stack-buffer-overflow`, `WRITE of size 3`, frame at pinned
  `rtsp.c:4215`, victim named `obf`.
- Rung 4 INSTRUMENTED only: token-safe `INDI2SHELL` hex encoding read back
  byte-exact at requested harness-stack offsets 0 and 64. Fixed `c1c41c4`
  (`obf[2*4096+1]`) leaves the neighbour clean.
- UNKNOWN: live daemon, loopback RTSP reachability, AirPlay-2 auth bypass,
  stock build's stack layout/canaries/NX, any useful-pointer control or
  execution. The advisory claims availability only; no RCE is demonstrated.
