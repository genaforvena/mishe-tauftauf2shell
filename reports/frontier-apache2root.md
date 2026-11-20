# Frontier brief: Apache2Root — CVE-2026-119618 (mod_http2 `assign_headers`)

Status: **frontier candidate, rung 0 (source-read + vendor claims only).
No local build, no trigger, no corruption observation in this brief.**
Written 2026-11-20 ~12:30Z by the `frontier` mind. All external material
below is cited as a claim; the only independently verified facts are the
patch diff and the affected-tree source lines quoted here.

## Verified ground truth (primary sources opened 2026-11-20)

- **Claim sources.** Apache HTTP Server 2.4 vulnerabilities page
  (`https://httpd.apache.org/security/vulnerabilities_24.html`, "Fixed in
  2.4.71", released 2026-11-11, critical); CVE record
  `CVE-2026-119618` (CNA Apache, published 2026-11-11, CWE-362,
  "Concurrent Execution using Shared Resource with Improper
  Synchronization … in `assign_headers()` can lead to RCE");
  oss-security announcement by Eric Covener 2026-11-11T12:19:30Z
  (`openwall.com/lists/oss-security/2026/11/11/13`).
- **Affected/fixed.** httpd **2.4.55 through 2.4.70**; standalone mod_h2
  from GitHub **2.0.8 through 2.0.42**; fixed in **httpd 2.4.71**.
  Discovery credited to Anthropic's OSS Scanner (2026-10-26 report) and
  Anthony Weems / Simon Scannell of Google Cloud Vulnerability Research
  (2026-11-03).
- **Claimed primitive.** Vendor description: heap corruption via
  unsynchronized concurrent access to a shared resource. Red Hat's CVE
  2026-119618 page states a worker thread writes into memory owned by the
  connection thread "through a shared, lock-free allocator", pre-auth,
  CVSS 3.1 9.8 (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`) and says "public
  research has demonstrated a reliable exploit against a
  default-configured server with mod_http2 enabled". CVE.org's ADP score
  for the same CVE is 8.1 with `AC:H` — the exploitability disagreement
  is itself evidence that reliability is configuration-dependent.
  Red Hat notes RHEL 9/10 packages give each HTTP/2 stream a separate
  allocator and rates those Important rather than Critical; httpd with
  only HTTP/1.1 (`Protocols http/1.1`) is not exposed.
- **Reliability claims are unverified.** Wiz's 2026-11-11 post says no
  exploit was available then; CSA's 2026-11-12 research note says it
  could not locate the primary exploit write-up and found no
  in-the-wild use. The "reliable exploit" sentence is a vendor claim,
  not an available artifact in this plant. Wiz also lists standalone
  mod_h2 "2.0.42 and newer" as patched, contradicting Apache's own
  "2.0.8 through 2.0.42" affected range — use Apache's range.
- **Consumer screen: PASSES here.** No CPU/instruction-set dependency is
  claimed for this bug, unlike Java4Shell (CVE-2026-114938, zero AVX-512
  flags on this Zen 3 host) and nginx CVE-2026-123007 (AVX-512-only
  published consumer). This host runs glibc 2.39; the relevant
  allocator behavior is ordinary glibc APR/malloc, not a missing
  hardware path.

## Source-bound mechanism (read as specification, not a claim)

Upstream fix: `apache/httpd@824beab` on the 2.4.x branch
("mod_http2: assign_headers update table (#975) (#977)", cherry-pick of
`5ed3928`), one changed line in `modules/http2/h2_request.c`:

```
-    apr_table_setn(req->headers, "Content-Length", "0");
+    apr_table_setn(r->headers_in, "Content-Length", "0");
```

Affected tree at tag `2.4.70`, same file, verified 2026-11-20:

```
329:  r->headers_in = apr_table_clone(r->pool, req->headers);
352:  cl = apr_table_get(req->headers, "Content-Length");
353:  if (no_body) {
354:      if (!cl && apr_table_get(req->headers, "Content-Type")) {
358:          apr_table_setn(req->headers, "Content-Length", "0");
```

`req->headers` is the `h2_request` header table created for the HTTP/2
stream (`h2_request_create()` / `h2_request_add_header()` write into it)
and is the object cloned into each `request_rec`. After the clone, the
buggy line mutates that shared stream table (`req->headers`) when a
request has `Content-Type` but no `Content-Length` and END_STREAM was
already seen (`no_body`). The fix mutates the private `r->headers_in`
instead. A concurrent `apr_table_setn` on the shared table while another
thread reads or appends it is the race window; APR tables are arrays of
`apr_table_entry_t` that can grow/realloc, so a racing write can leave a
thread operating on a stale array or a freed allocation. **That the race
actually produces heap corruption is the vendors' claim; the source
only establishes the unsynchronized shared-table mutation and the
one-line repair.** Exact allocator ownership and the C2/worker thread
interleaving remain UNKNOWN until a local build is observed.

## Cheapest local experiment that moves this up a rung

1. **Provision (next wake, standing approvals).** Fetch httpd tarballs
   `2.4.70` (affected) and `2.4.71` (fixed) plus their sha256 from the
   Apache release pages into `lab/src/`; build each in
   `lab/frontier/apache2root/` with ASan+UBSan, `--enable-http2`,
   event MPM, `h2c` enabled, binding **127.0.0.1 only**. No external
   probes, no target-list mode.
2. **Rung 1/2 — deterministic state oracle (secondary claim, must be
   checked locally).** Threat Landscape (2026-11-12) reports that an
   HTTP/2 HEADERS frame with `Content-Type`, no `Content-Length`, and
   END_STREAM set leaves `CONTENT_LENGTH` **unset** on vulnerable
   versions while 2.4.71 preserves it as `0`. Send that request through
   a loopback h2c client to an endpoint reflecting `CONTENT_LENGTH`
   (CGI/PHP) on both builds. If the differential appears, it proves the
   wrong table was written (a state failure) — it does **not** prove
   heap corruption. If it does not appear, that oracle is falsified and
   the claim is preserved as a negative result.
3. **Rung 3 — race under ASan.** From many concurrent h2c connections,
   repeatedly send the same `Content-Type`/no-`Content-Length`/
   END_STREAM HEADERS shape with varied header counts (to force APR
   table growth) while other streams add/parse headers, and watch for
   ASan reports in `h2_request.c` / `apr_tables.c`. Fixed 2.4.71 under
   identical traffic is the control. Failure to reproduce after a
   bounded sweep is a negative result, not evidence of safety.
4. **Rung 4 gate.** Only if ASan observes corruption: identify the
   victim allocation and the bytes/offsets actually controlled by the
   wire input; then attempt overlap or pointer control in the
   affected build, labeled per build. No rung-4 claim from a synthetic
   allocator shim.

## Feasibility assessment (ranking rationale)

- **Tractability: medium-high, first choice.** Small source diff with an
  exact line, no hardware gate, wire-only pre-auth trigger shape,
  loopback-able, fixed control available as a one-line differential.
- **Main risk: race determinism and allocator choice.** All observed
  aborts may be layout/timing-dependent; Red Hat's own note says
  per-stream allocators materially change exploitability, and the
  plant's nginx2root lesson says to check the real consumer before
  investing in placement mechanics. If the shared-table write only
  produces a benign missing `Content-Length` on our build, this stops at
  rung 2 and the candidate should be handed back with that negative.
- **Scope check.** No existing charter/window for Apache; `lab/apache2root/`
  in this repo is a PHP2Shell Apache/PHP-FPM fixture (`oom.php`,
  `php.ini`, `sess/`), **not** this CVE — no admission or lane exists
  yet. If rung 2+ is observed locally, hand the evidence to the
  operator for a dedicated mind/window; the frontier mind then moves
  to the next candidate.
- **Ranking against the rest of the shortlist (wall):**
  Apache2Root > Java4Shell (hardware-blocked) > Apache mod_http2
  CVE-2026-57941 (same target, secondary) > PHP cluster (PHP2Shell's
  lane) > SAP Web Dispatcher CVE-2026-109800 (no primary source yet).

## Open questions / unknowns

- Does a single `apr_table_setn` on `req->headers` really race with a
  competing access on this build, and which thread owns the table?
  UNKNOWN until instrumented.
- Is the "deterministic detection oracle" independent of the race, or
  merely the direct consequence of writing the wrong table? Both are
  consistent with the one-line diff; only the latter is expected.
- No public primary PoC was located; none was probed for or fetched
  from external systems beyond the cited read-only articles.
- No build, no ASan run, no HTTP request has been made for this
  candidate in this plant. Everything above rung 0 is a plan.
