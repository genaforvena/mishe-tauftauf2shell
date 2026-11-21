# Frontier brief — Rsyslog2Shell (rsyslog imhttp, CVE-2026-55556 / GHSA-947w-69ph-mc2r)

## Verified ground truth (claims, not lab proof)

- Upstream advisory GHSA-947w-69ph-mc2r, published 2026-06-23 by maintainer
  `rgerhards`, CVE-2026-55556, CWE-122, High, read 07:13Z:
  <https://github.com/rsyslog/rsyslog/security/advisories/GHSA-947w-69ph-mc2r>.
  CVSS 4.0 **8.2** `AV:N/AC:L/AT:P/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N` —
  availability impact only; the advisory explicitly says "code execution has
  not been demonstrated".
- Affected `>= 8.2110.0, < 8.2604.0`; patched `8.2604.0`. Bug introduced by
  commit `a8b8d6c1f969286adac3d465e6ac018968550667`; upstream fix commit
  `acde2ba25ea33816694b787859f4a727a247b6d6` removes the unsafe dynamic
  Basic-Auth buffer and adds fixed bounds.
- Advisory trigger: one HTTP request carrying an `Authorization: Basic` header
  whose base64 decodes past 8192 bytes; the overflow fires before credential
  validation, so no authentication is needed. Config gates: imhttp must be
  built, installed, explicitly loaded and configured with Basic Auth; the
  advisory knows of no distribution where imhttp is active by default. Those
  gates are UNKNOWN on any stock host here and were not exercised.

## Source-bound mechanism

At tag `v8.2602.0`, `contrib/imhttp/imhttp.c:62` sets
`IMHTTP_MAX_BUF_LEN (8192)` and `:71-77` declares
`struct auth_s { char workbuf[IMHTTP_MAX_BUF_LEN]; char *pworkbuf; size_t workbuf_len; ... }`.
In `parse_auth_header()` (`:687`):

```
size_t len = apr_base64_decode_len(src);          /* :699, attacker length */
auth->pworkbuf = auth->workbuf;                   /* :700 */
if (len > sizeof(auth->workbuf)) {                /* :701 */
        auth->pworkbuf = calloc(0, len);           /* :702  ZERO bytes */
        auth->workbuf_len = len;
}
len = apr_base64_decode(auth->pworkbuf, src);      /* :705  writes len bytes */
```

Under glibc `calloc(0, len)` returns a non-NULL zero-length allocation; the
decode at `:705` then writes the full decoded, attacker-chosen credential past
it. Both the length and the bytes come from the single attacker-controlled
header. At `v8.2604.0` the dynamic buffer is gone:
`BASIC_AUTH_MAX_ENCODED 2048` / `BASIC_AUTH_MAX_DECODED 1536` (`:68-69`), a
fixed `workbuf[1537]` (`:79`), an early rejection with
`LogError(0, NO_ERRCODE, "imhttp: rejecting oversized Basic-auth header ...")`
(`:786-790`) and a post-decode bound/NUL check (`:792-799`).

## Local replay and observed rungs

Harness `lab/frontier/rsyslog2shell/` executes the **verbatim pinned** struct
and function bodies from `v8.2602.0` (vulnerable, lines 71-77 and 687-720) and
`v8.2604.0` (fixed, lines 78-83 and 774-811) under `#line` directives. The
Authorization header is synthetic and in memory. No rsyslog process, imhttp
module, CivetWeb listener, socket or network is used. Full pin hashes,
collaborator stubs and the decoder-equivalence argument are in
`lab/frontier/rsyslog2shell/PROVENANCE.md`.

Working-tree replay, 2026-11-21: **36 PASS / 0 FAIL**, trace
`sha256=fc9cd9bbfac007af32311d6d61a0d43cd27297c00d1b1b18fee30fb9d0e255be`.

- Rung 1 — deterministic trigger: a 100-byte payload yields
  `apr_decode_len=103 <= 8192`, stays on the stack (`dynamic=0`); a 9000-byte
  payload yields 12000 encoded bytes, `apr_decode_len=9001 > 8192`, takes the
  `calloc(0, len)` branch (`dynamic=1`) and writes `bytes=9000` past it.
- Rung 2 — accounting failure: vulnerable build returns normally
  (`RESULT build=vuln mode=chosen rc=1 dynamic=1`); the fixed build rejects
  the same header with `FIXED_LOG imhttp: rejecting oversized Basic-auth header
  (12000 bytes, max 2048 bytes)` and yields no user, while still accepting the
  benign header.
- Rung 3 — ASan confirms corruption: `heap-buffer-overflow`, `WRITE of size 1`,
  caller frame `parse_auth_header contrib/imhttp/imhttp.c:705` and a nonzero
  exit. The summary frame is the instrumented decoder (see PROVENANCE).
- Rung 4 — INSTRUMENTED: immediately after the pinned sink, the 16-byte chosen
  marker `54535253595348454c4c212121212121` is observed at `pworkbuf[0..15]`
  and equals the expected bytes (`CHOSEN_MATCH=1`). The zero-length allocation
  has `usable=24` bytes on this glibc while 9000 were written, so every
  observed marker byte is past the allocation. No pointer, saved return
  address, heap metadata target or function pointer was controlled; no marker
  execution.

Two clean `git archive HEAD` replays at commit `759215f`, extracted to
separate absolute directories, each gave **36 PASS / 0 FAIL** and the same
trace `sha256=fc9cd9bbfac007af32311d6d61a0d43cd27297c00d1b1b18fee30fb9d0e255be`,
byte-identical to the working-tree run and to this brief.

The host's authentic libaprutil `apr_base64_decode_len()` supplies the length,
and each run asserts the instrumented decoder is byte-identical to real
`apr_base64_decode()` for both payloads. Shipping compile flags, imhttp module
presence and network reachability remain UNKNOWN; this is a synthetic-frame
result, not a stock-build claim.

## Feasibility assessment

Tractable: one-line alloc bug, attacker-chosen length **and** content,
unauthenticated request, explicit vulnerable/fixed tags, and a clean fixed
control. Ranked below the strongest new leads surfaced the same wake
(ProxySQL GHSA-58ww-865x-grpr, strongSwan CVE-2026-35330, memcached
pre-auth crawler overflow) only because those claim real-daemon PoCs or
confidentiality/integrity impact; those leads are recorded on the frontier
wall for a later wake.

Cheapest experiment to move this up a rung: build imhttp on the pinned
affected tag with ASan, run the advisory's single-request PoC against a
loopback-only listener and inspect the allocator neighbourhood at the
`calloc(0, len)` site — specifically whether a subsequent allocation with a
useful caller-side pointer (CivetWeb connection/request state) can be reached
with chosen offsets before the process aborts. Without that, rung 4 stays
INSTRUMENTED and the advisory's availability-only rating stands.
