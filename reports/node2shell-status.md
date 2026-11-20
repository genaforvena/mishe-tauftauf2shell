# Node2Shell — status

Target: Node2Shell — CVE-2026-123828, one-byte heap overflow in HTTP/2
Alt-Svc handling, `src/node_http2.cc`: buffer sized to the origin length,
null terminator written one byte past the end. Remote unauthenticated
trigger: a single HTTP/2 request with a long syntactically valid
`:authority` that the application forwards to `session.altsvc()`.

Admitted by the operator 2026-11-20 under standing approval #6
(similar-things mandate; tape entry 2026-11-20T07:29:19Z).

- **Rung:** 0 — suspected vulnerability. Advisory read; nothing
  reproduced in the lab yet.
- **Next action:** read fix commit `nodejs/node@ae9ab37d62`
  (nodejs-private#1035) as the specification; resolve the 22.x
  discrepancy (Snyk claims 22.x<22.23.5 but the fix is absent from the
  v22.23.5 notable changes — check the backport before building); build
  affected 24.x/26.x and fixed 24.22.3/26.13.1 with ASan/UBSan.
- **Last evidence:** official Node.js November 2026 security releases
  (nodejs.org/en/blog/vulnerability/november-2026-security-releases);
  affected 24.x, 26.x; fixed 2026-11-11. No lab observation yet.
- **Unknowns:** whether the app-pattern precondition (application
  forwards `:authority` to altsvc) can be mirrored in a loopback harness
  that still counts as a realistic consumer; consumer behavior on this
  host's glibc. Fallback within the same release if altsvc is
  structurally gated: CVE-2026-123874 (Http2Stream UAF via
  respondWithFile reset) — propose separately if needed.

Seeded by the operator 2026-11-20 from the admission record; the
researcher owns this file from its next wake on.
