# Frontier brief: Apache2Root — CVE-2026-119618 (mod_http2 `assign_headers`)

Status: **frontier candidate, rung 2 (deterministic state differential
observed locally on two ASan builds). No heap corruption observed yet.**
Written 2026-11-20 ~12:30Z by the `frontier` mind; local observation
appended 2026-11-20 13:00Z. All external material below is cited as a
claim; the independently verified facts are the patch diff, the source
lines quoted here, and the local run in the final section.
Written 2026-11-20 ~12:30Z by the `frontier` mind; rung-2 observation
appended 13:00Z. All external material below is cited as a claim.

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
- A single-request probe produced no ASan report; the race/corruption
  claim needs a concurrent workload, which is the next bounded step.

## Local observation 2026-11-20 13:00Z — rung 2 confirmed

Provisioning and build (all under standing approval #5, loopback only):
`lab/src/httpd-2.4.70.tar.bz2` and `httpd-2.4.71.tar.bz2` match their
published `.sha256` exactly (`1eefd7dc…bafc3`, `2bc5da5a…8de62`);
`nghttp2-1.64.0.tar.xz` is provisioned likewise. The one-line diff was
re-read from both tarballs before building (`h2_request.c:353`, 2.4.70
uses `req->headers`, 2.4.71 uses `r->headers_in`). Reproducible driver:
`lab/frontier/apache2root/build.sh`; harness: `oracle.sh` with CGI
endpoint `oracle-cgi.sh`; raw logs under `lab/frontier/apache2root/logs/`.
gcc `-fsanitize=address,undefined -O1 -g`, event MPM, mod_http2 2.0.42
against nghttp2 1.64.0, static-PIC nghttp2, `Protocols h2c http/1.1`,
`H2Direct on`, bind 127.0.0.1 ports 7080 / 7171.

Exact input (from `oracle.sh`): `curl --http2-prior-knowledge` GET
`http://127.0.0.1:<port>/cgi-bin/oracle` with `Content-Type: text/plain`,
no `Content-Length`, END_STREAM on HEADERS. `oracle-cgi.sh` prints the
CGI environment, which mod_cgi derives from `r->headers_in`
(`server/util_script.c:219`).

Observed bytes (`logs/oracle-run5.log`), both HTTP/2 200:

- affected 2.4.70: `CONTENT_LENGTH=[<UNSET>]`, `CONTENT_TYPE=[text/plain]`
- fixed 2.4.71: `CONTENT_LENGTH=[0]`, `CONTENT_TYPE=[text/plain]`

Interpretation: the vulnerable build wrote `Content-Length: 0` into the
stream table `req->headers` instead of the per-request table, so the
request never saw it. This is a **rung-2 state failure** and confirms the
one-line mechanism from source. It is **not** heap corruption: no ASan or
UBSan report was produced by this single-request probe. The vendor's
race/corruption claim remains UNVERIFIED locally. Source cross-reference
still supports a real cross-thread hazard: c1 stores `stream->request`
(`h2_stream.c:986`) and reads `req->headers` (`h2_stream.c:991`,
`h2_mplx.c:487`), while the c2 worker mutates that same table in
`assign_headers()`.

Build failures preserved as negative evidence: (1) static nghttp2 built
without `-fPIC` broke `mod_http2.la` linking with `R_X86_64_PC32 against
stderr`; fixed by `--with-pic`. (2) A clang build compiled but every
startup aborted with "Your application is linked against incompatible
ASan runtimes" — static ASan in `bin/httpd` versus `libasan.so.8` in the
DSOs (`ldd`); fixed by building both with gcc so the runtime is dynamic
and shared.

## Bounded rung-3 sweep 2026-11-20 13:01Z — no ASan report (negative)

`lab/frontier/apache2root/race.sh` ran 3 rounds x 200 trigger-shaped h2c
streams x 65 headers each against the affected 2.4.70 ASan build on
127.0.0.1:7080, with `LogLevel http2:trace4` and
`H2MaxSessionStreams 1000` to widen the cross-thread window. Raw output:
`logs/race-run1.log`. All curl rounds exited 0. No `asan-2.4.70-race.*`
report file, no `AddressSanitizer` / `runtime error` / `SEGV` / child
crash marker in the error log. The `h2_stream(...,CLEANUP): cleanup, c2
is running, abort` lines are ordinary stream teardown when curl closes
the connection, not process aborts. **Rung 3 not observed** in this
bounded sweep; that is a negative result, not evidence of safety. The
race/corruption claim remains UNVERIFIED. A dedicated mind may revisit
with a longer, better-instrumented interleaving; frontier does not
duplicate the lane after handoff.
