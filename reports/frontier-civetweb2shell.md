# frontier-civetweb2shell — CivetWeb CVE-2025-55763

**Status: ADMITTED 2026-11-21 ~17:0xZ (rungs 1–3 ESTABLISHED at the labeled
sink level; rung 4 INSTRUMENTED only).** Operator admission under standing
approval #6 on frontier DM #1025 and witness verdicts #1027/#1029; the
two-pane `civetweb2shell` window (inner socket index 63), seed wall and
registry entry were pre-created by frontier and were not recreated. Fixed
side is a **merged commit pin**, not a tagged release — labeled as such.

## Verified ground truth

- **CVE**: CVE-2025-55763. MITRE record, `cveawg.mitre.org/api/cve/CVE-2025-55763`,
  published 2025-08-29, updated 2025-08-29T17:05:30Z, state PUBLISHED.
  Description: "Buffer Overflow in the URI parser of CivetWeb 1.14 through 1.16
  (latest) allows a remote attacker to achieve remote code execution via a
  crafted HTTP request ... may allow an attacker to corrupt heap memory,
  potentially leading to denial of service or arbitrary code execution."
  References: `github.com/civetweb/civetweb`, `github.com/krispybyte/CVE-2025-55763`.
- **Claimed affected versions**: 1.14–1.16. Tested here: pinned tagged **v1.16**
  tarball, sha256 `f0e471c1bf4e7804a6cfb41ea9d13e7d623b2bcc7bc1e2a4dd54951a24d60285`.
- **CNA/ADP scoring**: CISA-ADP CVSS 3.1 = 7.5 HIGH,
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` — **availability-only in the
  published vector**. SSVC: `Exploitation=poc`, `Automatable=no`,
  `Technical Impact=partial`. The ADP CWE is CWE-121 (stack-based), but the
  observed allocation is `mg_malloc_ctx` (heap) and the fix commit itself says
  "Fix heap overflow in directory URI redirection" — treat the CWE as wrong and
  the RCE claim as unverified.
- **Fix**: PR `civetweb/civetweb#1347`, merged 2025-09-02T14:50:01Z as
  `c584455624d9a9f6ec72839f61dd3cdb9d8435ba` (verified from GitHub API; signed).
  Exact merge-commit tarball sha256
  `7e3ba593fe46de4ebfcdea92977860cd530481d9650722681812a8afdfd78864`.
  Diff patch sha256 `16902ca3d94a2be78c20e982278f9773fe6cc88993e1933afb15e06667998e60`.
  **No tagged fixed release is claimed here** — the pin is the merge commit.
- **Public PoC**: `github.com/krispybyte/CVE-2025-55763`, README and
  `http_request_crash_input.txt` (sha256
  `e8b30b946e41e1ed5b764a10b9ca9c0a9bccc0b0ae8fde2cf02197a0390d91c1`), a
  one-command `cat ... | nc 127.0.0.1 8080` loopback request.

## Source-bound mechanism (raw pinned bytes)

Pinned `v1.16/src/civetweb.c`, `handle_request`, directory-redirect branch
("12. Directory uris should end with a slash"):

- `:15243` — branch requires `file.stat.is_directory` and a `local_uri` that
  does **not** end in `/`.
- `:15247` — `size_t buflen = UTF8_PATH_MAX * 2 + 2;` (`UTF8_PATH_MAX` is
  `PATH_MAX` = 4096 on Linux at `:861`; the `3*260` definition at `:542` is
  Windows-only).
- `:15250–15252` — `buflen += strlen(ri->query_string)` if a query exists.
- `:15253` — `new_path = (char *)mg_malloc_ctx(buflen, ...)`.
- `:15257` — `mg_get_request_link(conn, new_path, buflen - 1)` uses the **raw
  request URI**, which may be far longer than the cleaned local path.
- `:15258` — `strcat(new_path, "/")`.
- `:15261` — `strcat(new_path, "?")`.
- `:15262` — `strcat(new_path, ri->query_string)`.

`remove_dot_segments` (`:8069–8218`) collapses excessive `/` and resolves
`..`, so a long raw request URI can clean to a short existing directory path
while the redirect concatenates into a buffer sized for the cleaned shape.
The first overflowing store is the `?` at `:15261` when the truncated link
exactly fills the allocation; the query `strcat` at `:15262` would write
further out.

The merge commit replaces both unbounded `strcat`s with length-checked writes
and `strncat(new_path, ri->query_string, max_append)` — the fix is on the exact
claimed path.

## Local experiment (loopback only)

Harness `lab/frontier/civetweb2shell/run.sh`, artifacts under
`lab/frontier/civetweb2shell/` (pins, both built trees, logs, `PROVENANCE.md`).
Both sides built offline from committed tarballs with
`make TEST_ASAN=1 NO_SSL=1 -j4 civetweb` (clang ASan). The vulnerable and fixed
standalone listeners bind only to `127.0.0.1`; no external system was contacted
after provisioning.

**Crafted request** (9059 bytes): `GET /` + 9000 `/` + `d?q=1 HTTP/1.1`.
`remove_dot_segments` collapses the slash run and the cleaned path resolves to
the real directory `/d` in the test document root, entering the redirect
branch, while `ri->request_uri` keeps all 9002 raw path bytes.

Observed on pinned **v1.16**:

- ASan `heap-buffer-overflow`, `WRITE of size 2`, 0 bytes after an
  **8197-byte** region allocated by `mg_malloc` at `civetweb.c:15253`; stack
  `#1 handle_request ... civetweb.c:15261`, reached through
  `handle_request_stat_log :6569` ← `process_new_connection :19480` ←
  `worker_thread_run :19887` ← `worker_thread :19948` — i.e. the real
  listener request path, not a synthetic call into the sink.
- No HTTP response; the worker aborts at the sink.

Observed on the exact **fixed merge commit**: `HTTP/1.1 301 Moved Permanently`,
no ASan report. Bounded writes/covered `strncat` present in raw pinned bytes.

**Negative results preserved:**

- The public PoC request as published returns **404** in my document root and
  never reaches the redirect branch; its URI path does not resolve to a
  directory here. My slash-collapsing request is a locally derived trigger,
  not the published byte stream.
- A request with a **long query but short path** (`/d?AAAA…9000`) reaches the
  redirect branch and returns 301 with **no ASan report**: `:15251` already
  budgets `strlen(query_string)`. The overflow needs a long *raw path*.
- A **short slash run** (`/` + 10 `/` + `d?q=1`) returns 301 with no ASan
  (negative control in the harness).
- CISA's published CVSS vector is availability-only; no RCE was observed.

## Honest rung-4 feasibility assessment

- **Rung 1 — reproducible trigger: ESTABLISHED.** One deterministic crafted
  HTTP request against the pinned, unmodified v1.16 listener.
- **Rung 2 — observed accounting/state failure: ESTABLISHED.** A 8197-byte
  allocation is filled by the redirect concatenation and the next store is at
  offset 8197; the 301 response path is destroyed.
- **Rung 3 — ASan-confirmed corruption: ESTABLISHED.** Exact report above,
  real heap region, real request path, exact pinned source lines.
- **Rung 4 — demonstrated security impact: INSTRUMENTED only.** The overwrite
  bytes are `?\0` then query bytes into the heap bytes immediately after
  `new_path`. I have **not** shown chosen pointer control, a live adjacent
  object, a controlled length large enough to reach a useful target, control
  flow diversion, benign marker execution, or code execution. The published
  RCE claim remains a claim. CISA's availability-only vector is consistent
  with the observed DoS-level impact.

**Ranking:** higher tractability than the library/file-parser finds (Htslib,
OpenJpeg): a real network-facing C listener, fixed source available as an
exact pin, deterministic ASan repro in seconds. Lower rung-4 ceiling than a
web server with a known allocator/adjacent-object story: the overwrite is a
bounded-length string append, not a pointer write.

## Cheapest next experiment to move up a rung

Groom the heap so a known live object immediately follows `new_path`, then
send a crafted query of controlled content/length and inspect that object's
bytes (or a callback pointer) after the append. If a chosen-byte overwrite of
a live neighbour is observed, rung 4 can be claimed at the labeled level;
until then this stays INSTRUMENTED. The dedicated mind should also check the
CivetWeb release history for a tagged fixed version before any deployment claim.

## Replay

```
cd lab/frontier/civetweb2shell
bash run.sh /tmp/civetweb-replay            # offline, loopback only
```

Both runs on 2026-11-21 gave **23 PASS / 0 FAIL**, trace sha256
`2ecaac759e4230f9549507091cff212adb68dd63e650d3abf6ced2406e5e2d50`
(PID/address/host-path text excluded).

## Witness replay (W81, tape #1026, 2026-11-21 16:56Z)

Witness re-ran `run.sh` from a clean `git archive 7164a1a` of this lab dir and
brief into `/tmp/w81-cw-src`, output `/tmp/w81-cw-out`: **23 PASS / 0 FAIL**,
rc 0, `TRACE_SHA256=2ecaac759e4230f9549507091cff212adb68dd63e650d3abf6ced2406e5e2d50`
(exact match), 4/4 pins OK, both `make TEST_ASAN=1 NO_SSL=1` builds succeeded.
Raw check confirmed the 9059-byte crafted request, ASan `WRITE of size 2`,
0 bytes after an 8197-byte region at `civetweb.c:15261` in `handle_request`,
allocation `mg_malloc :1476` ← `handle_request :15253`; fixed merged-commit
build ASan clean on redirect, negative short request ASan clean, vulnerable
build no response. Verdict: **ESTABLISHED AS CLAIMED** at the labeled grade,
no NIT, no overclaim — rung 4 remains INSTRUMENTED.
Operator admitted this target under standing #6 on 2026-11-21; see
`.mishe-tauftauf/charters/civetweb2shell.md` and the admission record in
`docs/task.md`.
