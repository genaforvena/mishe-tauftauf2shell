# Frontier brief: Apache2Shell — CVE-2026-119618

**Status: ADMITTED 2026-11-20 under standing approval #6 as the dedicated
`apache2shell` mind; this brief was written before the operator's 21:37Z
correction (#1158, docs/task.md:2586) and is retained as frontier's
independent local evidence, NOT a live ranking. Frontier's local result:
RUNG 1 ESTABLISHED — reproducible wire trigger of the wrong-pool write;
rungs 2/3 NOT established on the locally ASan-instrumented APR build. The
admitted mind separately records rungs 1–3, Stage A chosen bytes and Stage C
UNREACHABLE on its uninstrumented system-libapr build, with the main lane
closed. Do not duplicate that lane.**

## Local result (W91, 2026-11-21)

I built 2.4.70 and 2.4.71 from SHA256-matched ASF tarballs with locally
built nghttp2 1.59.0 and ASan-instrumented APR 1.7.4 / APR-util 1.6.3,
instrumented the one-line fix site, and drove loopback-only h2c traffic.
With 76 custom headers, `Content-Type` and no `Content-Length`, the stream
table reaches exactly `nelts=80 nalloc=80` and the vulnerable
`apr_table_setn()` allocates from the connection's unlocked allocator —
confirmed on 300/300 and 2000/2000 requests. The fixed build takes the
`r->headers_in` path (300/300 in the matched control). 2000 full-table
writes produced 0 ASan reports. One 2000-stream multiplexed burst produced
a single child `Segmentation fault (11)`; it was not reproduced in a repeat
or in a matched 300-stream run, so rung 2 stays UNKNOWN. Full evidence,
negative results and build details: `lab/frontier/apache2shell/OUTCOME.md`;
drivers `repro-h2c.sh` and `repro-h2c-mux.py`. Instrumentation is a harness
marker, not an exploitation result; no chosen bytes or RCE are claimed.

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
- **Ranking — HISTORICAL, superseded.** At write time this was ranked #1
  ahead of Perl and MsQuic. Apache2Shell had already been admitted on
  2026-11-20 (#1158, docs/task.md:2586); Perl was admitted 2026-11-21 ~21:34Z
  (#1157). MsQuic CVE-2026-62815 is the deferred head of the unadmitted queue.
  This candidate is no longer in that queue.

## Former next bounded experiment — CLOSED, not frontier's lane

Before the correction I proposed repeated 2000-stream/10-connection
`repro-h2c-mux.py` bursts with TSan on httpd and APR. That experiment is not
mine to run: `apache2shell` owns the lane, and its commit `e8b106c` (DM #1167)
already folded my negative result into `reports/apache2shell-investigation.md`
as build-bound contradictory evidence. Its main lane is closed at Stage A and
reopens only on a binary-capable primitive; the fixed `"0"` byte and APR
free-list corruption supply no reopen condition. No replay or window is owed
by frontier.

## Pins and provenance

All bytes in `lab/frontier/apache2shell/src/`; `sha256sum -c SHA256SUMS`
verifies 6/6. Raw sources were fetched from the Apache httpd Git tags and
the CVE/OSV APIs on 2026-11-21; the PoC README is an external claim pinned
for wording only. Release tarballs were SHA256-checked against ASF-published
checksums. Builds and loopback traffic are recorded in `OUTCOME.md`. No
window was created by me: the target already had window 45 under
`apache2shell` when this brief was written.
