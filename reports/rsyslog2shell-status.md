# rsyslog2shell — status

Admitted 2026-11-21 ~07:2xZ by the operator under standing approval #6 on
frontier's commit `759215f` and brief `reports/frontier-rsyslog2shell.md`.
Claim source: maintainer advisory GHSA-947w-69ph-mc2r, CVE-2026-55556,
published 2026-06-23 by `rgerhards`, CWE-122, High; CVSS 4.0 **8.2**
`AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` — availability
impact only, and the advisory explicitly says "code execution has not been
demonstrated". Affected `>= 8.2110.0, < 8.2604.0`; patched `8.2604.0`. Bug
introduced by `a8b8d6c1f969286adac3d465e6ac018968550667`; upstream fix
`acde2ba25ea33816694b787859f4a727a247b6d6` removes the dynamic Basic-Auth
buffer and adds fixed bounds. Claimed trigger: one HTTP request with an
`Authorization: Basic` header whose base64 decodes past 8192 bytes; the
overflow fires before credential validation, so no authentication is needed.
Config gates — imhttp must be built, installed, explicitly loaded and
configured with Basic Auth; the advisory knows of no distribution where
imhttp is active by default — are UNKNOWN on any stock host here and were
not exercised. Brief: [frontier-rsyslog2shell.md](frontier-rsyslog2shell.md).
Pins and raw URLs: `lab/frontier/rsyslog2shell/PROVENANCE.md`.

- Harness: `bash lab/frontier/rsyslog2shell/run.sh <outdir>` — 36 PASS /
  0 FAIL, `ALL CHECKS PASSED rc 0`, canonical trace SHA-256
  `fc9cd9bbfac007af32311d6d61a0d43cd27297c00d1b1b18fee30fb9d0e255be`.
- Operator replay ~07:20Z from two clean `git archive HEAD` (`ba9a240`)
  extractions into separate absolute directories: 36 PASS / 0 FAIL and
  `ALL CHECKS PASSED rc 0` in both, trace
  `sha256=fc9cd9bbfac007af32311d6d61a0d43cd27297c00d1b1b18fee30fb9d0e255be`
  — byte-identical between directories and to the brief.
- Rungs 1/2/3 on verbatim pinned upstream blocks from `v8.2602.0`
  (`contrib/imhttp/imhttp.c` struct `:71-77`, function `:687-720`) and
  `v8.2604.0` (struct `:78-83`, function `:774-811`): a 100-byte payload
  yields `apr_decode_len=103 <= 8192` and stays on the stack (`dynamic=0`);
  a 9000-byte payload gives 12000 encoded bytes, `apr_decode_len=9001 >
  8192`, takes the `calloc(0, len)` branch (`dynamic=1`) and writes 9000
  chosen bytes past the zero-length allocation. The vulnerable build returns
  normally; the fixed build rejects the same header with
  `imhttp: rejecting oversized Basic-auth header (12000 bytes, max 2048
  bytes)` and still accepts a benign header. ASan reports
  `heap-buffer-overflow`, `WRITE of size 1` with the pinned caller frame
  `parse_auth_header contrib/imhttp/imhttp.c:705` (the ASan summary frame is
  the instrumented decoder, not upstream source).
- Rung 4 INSTRUMENTED only: immediately after the pinned sink, the 16-byte
  chosen marker `54535253595348454c4c212121212121` is observed byte-exact at
  `pworkbuf[0..15]` (`CHOSEN_MATCH=1`). On this glibc the zero-length
  allocation has `usable=24` bytes while 9000 were written, so every
  observed marker byte is past the allocation. No pointer value, saved
  return address, heap-metadata target, function pointer, control-flow
  diversion or marker execution was controlled or attempted.
- UNKNOWN: live rsyslog process, imhttp module presence, CivetWeb listener,
  the HTTP request path, shipping compile flags, network reachability, the
  post-overflow allocator neighbourhood and any caller-side pointer that a
  later allocation could place there. All external claims — reachability,
  CVSS, severity, `AT:P` — remain claims. No probe was sent off loopback.
  Witness replay was requested in the handoff; no verdict at admission.

Cheapest next rung: build imhttp on the pinned affected tag with ASan, run
the advisory's single-request PoC against a loopback-only listener and
inspect the allocator neighbourhood at the `calloc(0, len)` site —
specifically whether a subsequent CivetWeb connection/request-state
allocation with a useful caller-side pointer can be reached with chosen
offsets before the process aborts. Without that, rung 4 stays INSTRUMENTED
and the advisory's availability-only rating stands.
