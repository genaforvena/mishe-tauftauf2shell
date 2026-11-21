# Frontier brief: Apache2Shell — CVE-2026-119618

**Verdict: RANKED CANDIDATE #1 (unadmitted), RUNG 0 — claim and source pins verified, no local build or traffic yet.**

## Verified ground truth

| Item | Value |
|---|---|
| CVE | CVE-2026-119618 |
| Title | Apache HTTP Server: `mod_http2`: heap corruption and RCE in `assign_headers()` |
| CNA | Apache Software Foundation, published 2026-11-11 |
| Affected | httpd **2.4.55 through 2.4.70**; standalone `mod_h2` **2.0.8 through 2.0.42** |
| Fixed | httpd **2.4.71** (released 2026-11-11); `mod_h2` **2.0.43** |
| CWE | CWE-362 (concurrent execution with improper synchronization); consequence is heap corruption |
| Vendor CVSS | CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H (OSV record) |
| Fix commit | `824beab9b9424d6cfb29595248fdbf6c3dddeab1` "mod_http2: assign_headers update table (#975) (#977)", 2026-11-09T02:54:20Z, one file `modules/http2/h2_request.c`; trunk original `5ed39287660daacd1233cb9bbc984b25fa9a4fe3` |

Primary sources: [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-119618), [OSV](https://osv.dev/vulnerability/CVE-2026-119618), [Apache httpd 2.4 security page](https://httpd.apache.org/security/vulnerabilities_24.html), [fix commit](https://github.com/apache/httpd/commit/824beab9b9424d6cfb29595248fdbf6c3dddeab1).

**Claim (not independently reproduced here):** a public PoC repository
[googlesky/CVE-2026-119618](https://github.com/googlesky/CVE-2026-119618)
publishes a containerised ASan/TSan differential: 2.4.70 crashes, 2.4.71
clean, plus a published-workaround (`Protocols http/1.1`) check. Its README
claims a body-less HTTP/2 request with `Content-Type`, no `Content-Length`
and 79 regular headers fills the 80-entry header table so the vulnerable
`apr_table_setn()` grows it to 160 entries (3840 B → 8 KB allocation) from
the **connection's unlocked APR allocator**, racing the connection thread's
free-list writes. Treat all of this as a claim to reproduce, not fact.

## Source-bound mechanism (verified from pinned tag bytes)

I fetched `modules/http2/h2_request.c` at the raw `2.4.70` and `2.4.71` Git
tags and diffed them. The release fix is exactly one line, at 2.4.70
`h2_request.c:353` inside `assign_headers()`:

```diff
-                apr_table_setn(req->headers, "Content-Length", "0");
+                apr_table_setn(r->headers_in, "Content-Length", "0");
```

`r->headers_in` is the per-request clone created earlier in the same
function (`apr_table_clone(r->pool, req->headers)`); `req->headers` is the
stream's table, whose pool descends from the connection/session pool. The
branch only runs when `no_body && !cl && Content-Type` is present and
`!is_connect`. This is a **wrong-pool write**, not an arithmetic overflow:
the attacker chooses whether the branch runs and when the table is full, but
the written bytes are the fixed string `"0"` and the corrupted object is an
APR allocator free list shared between threads. The upstream fix removes the
cross-thread allocation entirely, which makes a clean vulnerable/fixed
differential plausible.

## Rung-4 feasibility — honest assessment

- **Why promising.** Wire-facing by construction (httpd is the server; no
  separate embedding consumer needed). Unauthenticated, network-reachable,
  critical vendor severity, public differential harness, tagged vulnerable
  and fixed builds with a one-line delta. This is the cheapest path to a
  clean rung-1/rung-2/rung-3 result in the current queue.
- **Why not a forecast of rung 4.** CWE-362, so rung 1 needs a deterministic
  79-header `h2c` trigger and a race window; rung 2 is a TSan/allocator
  state failure, not a simple counter; rung 3 (ASan heap corruption) may
  appear as allocator-internal crashes rather than a clean OOB report. Rung
  4 requires showing control (overlapping allocations or chosen bytes at
  chosen offsets), which the `"0"`-string write does not give directly.
  ASLR/heap-shape escalation and any actual command execution are UNKNOWN.
- **Ranking.** #1 ahead of Perl (CVE-2026-15534, AV:L/no wire path) and
  MsQuic (deferred): this is the only fresh candidate with a vendor-critical
  network primitive, a tagged fix and a published PoC to replay.

## Cheapest local experiment (next rung)

1. Build 2.4.70 and 2.4.71 from pinned release tarballs with APR 1.7.4 /
   APR-util 1.6.3, `--enable-http2=shared`, ASan and a separate TSan build,
   prefork MPM, `Protocols h2c http/1.1`, bound to 127.0.0.1 only.
2. Drive the published 79-header, no-body, `Content-Type`, no-
   `Content-Length` request with a stdlib HTTP/2 client from the public PoC
   repo, first reading its harness and reimplementing only the request
   shape — do not trust its verdict strings.
3. Record vulnerable ASan/TSan reports and fixed-build silence with exact
   builds, inputs, exit codes and sanitizer text. If rung 3 lands, attempt
   a benign marker at an overlapping-allocation target; label any in-process
   marker as rung-4 mechanics, not rung 5.

## Pins and provenance

All bytes in `lab/frontier/apache2shell/src/`; `sha256sum -c SHA256SUMS`
verifies 6/6. Raw sources were fetched from the Apache httpd Git tags and
the CVE/OSV APIs on 2026-11-21; the PoC README is an external claim pinned
for wording only. No build, no traffic and no window have been created by
this brief.
