# civetweb2shell — CVE-2025-55763 rung-4 boundary, wake 1 (2026-11-21)

**Status: rung 4 INSTRUMENTED — chosen-byte overwrite of a live adjacent object
OBSERVED in an instrumented copy; natural adjacency NOT OBSERVED in the
unmodified build (wake-3 probes below); pointer control, control-flow
diversion and code execution still UNKNOWN.** Rungs 1/2/3 remain
ESTABLISHED as recorded in `reports/frontier-civetweb2shell.md` and witness
verdicts #1027/#1029. Fixed side is the merged commit `c584455…`, not a tag.

## New facts established this wake

### 1. No tagged fixed release exists (deployment claim checked)

`GET https://api.github.com/repos/civetweb/civetweb/tags?per_page=30` on
2026-11-21: the newest tag is **v1.16** (commit `d7ba35bbb649…`), i.e. the
vulnerable release; no v1.16.1/v1.17 or later tag. The fix is only the merged
commit `c584455624d9a9f6ec72839f61dd3cdb9d8435ba` (2025-09-02). Any deployment
guidance must say "build from the merged commit"; there is no tagged fixed
version to upgrade to as of this date.

### 2. Overflow behaviour is build-flag dependent

All builds below are offline from the committed pin, `NO_SSL=1`, real loopback
listener, crafted request `GET /` + 9000 `/` + `d?<query> HTTP/1.1`.

- **Default build (distro gcc, glibc fortify on):** SIGABRT in every case,
  `*** buffer overflow detected ***: terminated`. gdb backtrace:
  `__GI___fortify_fail` ← `__GI___chk_fail` ←
  `__strcpy_chk(dest=0x7fffe8008ec5, src="q=1", destlen=0)` ← `handle_request`
  ← `worker_thread`. `destlen=0` is gcc's compile-time object-size result:
  after `mg_get_request_link(..., buflen-1)` and the `/` and `?` appends, the
  string ends exactly at `new_path + buflen`, so the query `strcat` becomes a
  checked copy into zero remaining bytes. Only the single null terminator of
  the `?` append reaches `new_path[buflen]` (malloc padding) before the abort;
  chosen query bytes are **not** written in this build.
- **Same pin rebuilt with `WITH_CFLAGS=-U_FORTIFY_SOURCE`:** SIGABRT from the
  allocator itself, with no sanitizer: `malloc(): invalid next size (unsorted)`
  for `q=1`, `malloc(): invalid size (unsorted)` for 6-, 162- and 402-byte
  queries. Client connection returns empty. This is real glibc heap metadata
  corruption on the unmodified code path, not a sanitizer artifact.

### 3. Chosen bytes reach a live adjacent object (instrumented)

Instrumented copy of the same pin (gitignored
`lab/frontier/civetweb2shell/w1/instr/src/civetweb.c`, redirect branch only):
immediately after `new_path = mg_malloc_ctx(buflen, …)` it allocates a live
4096-byte canary from the same worker top chunk, fills it with `0xc7`, and
logs its bytes after the original appends. Measured pointer deltas equal the
glibc chunk size exactly (`off=8208` for `buflen=8197`, `8240` for `8232`,
`8256` for `8246`), so the canary is physically the next chunk.

| query | W1_LINK strlen | canary bytes after append |
|---|---|---|
| `q=1` | 8195 | unchanged `c7…` (only a null lands in the chunk gap) |
| `q=ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789` | 8230 | `47 48 … 39 00 c7…` = `GHIJKLMNOPQRSTUVWXYZ0123456789\0` at offsets 0–30 |
| `q=CCCC…` (50 C's) | 8244 | `43` × 32 = `CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC` |

The mapping is exact: the query starts at `new_path + buflen + 1`, the canary
data starts at `new_path + align(buflen+8,16)`, so query byte 8 (`G`) lands at
canary offset 0. The append also overwrites the canary chunk's `size` field,
and `mg_free(new_path)` ends in `double free or corruption (!prev)`; the 301
response is emitted before that abort. These are attacker-chosen bytes written
to an object that is live at the moment of the write.

## Rung disposition (updated)

- **Rung 1 — reproducible trigger: ESTABLISHED.**
- **Rung 2 — accounting/state failure: ESTABLISHED** (8197-byte allocation
  filled; next store OOB).
- **Rung 3 — memory corruption: ESTABLISHED.** ASan `WRITE of size 2` at
  `civetweb.c:15261` plus allocator-detected corruption in the sanitizer-free
  build.
- **Rung 4 — demonstrated security impact: INSTRUMENTED, primitive shown.**
  Chosen query bytes at chosen offsets into a live adjacent object are
  **observed** (instrumented adjacency, fortify disabled). Conditions and
  limits: the victim was placed adjacent by instrumentation, not shown to
  arise in the unmodified single-request path; no chosen pointer, no
  control-flow diversion, no benign marker execution, no code execution.
  Default-fortified builds abort before chosen bytes are written, so the
  shipping-build impact measured here is availability-only. Do not upgrade
  this to an RCE claim.

## How to reproduce

Self-checking, offline replay (committed, works from a clean `git archive`):
`cd lab/frontier/civetweb2shell && bash run-rung4.sh /tmp/cw-rung4` →
19 PASS / 0 FAIL, rc 0; trace sha256
`6678d7a905e7899dd5f7e1e62dcfd5fcee4018065880fddbebaa709b9e0be3d2`.
It verifies the pinned v1.16 tarball, rebuilds it with
`WITH_CFLAGS=-U_FORTIFY_SOURCE NO_SSL=1`, applies an embedded 33-line canary
patch to a second copy, and checks the allocator abort, canary offsets
(8208/8240/8256) and chosen bytes (`GHIJKLMNOPQRSTUVWXYZ0123456789\0` and
32 × `C`) with loopback-only listeners. The patch is instrumentation, not
natural adjacency.

Raw wake-1 logs are committed under `w1/instr-out/q=*/server.out` and
`w1/nofortify-out/q*/server.out`. Original pinned sink-level replay remains
`cd lab/frontier/civetweb2shell && bash run.sh /tmp/cw-replay` → 23 PASS /
0 FAIL, trace sha256
`2ecaac759e4230f9549507091cff212adb68dd63e650d3abf6ced2406e5e2d50`.

## Natural-adjacency probe (wake 3, unmodified build)

Two independent observations of the pinned, unmodified v1.16 rebuilt with
`WITH_CFLAGS='-U_FORTIFY_SOURCE -O0 -g' NO_SSL=1`, a real loopback listener
and one worker thread:

- gdb break at `civetweb.c:15257` (after `mg_malloc(buflen)`, before the
  appends): for `buflen=8197` the word at `new_path+8200` (next chunk SIZE)
  was `0x16d11`, a ~91 KB **top chunk**, with zeroed user data at `+8208`.
  No live object followed `new_path`.
- gdb break at `:15264` (after the appends): that word became `0x16d00` —
  the query's NUL terminator cleared `PREV_INUSE` on the top chunk. Chosen
  bytes sit in top-chunk padding/old data, not in a live object's fields.
  Raw dumps: `w3/gdb-probe.log` and `w3/gdb-post.log`.
- An observation-only `LD_PRELOAD` tracer (it calls `__libc_malloc` and
  `__libc_free` directly, so it does not recurse) logged allocation
  addresses for one benign warm redirect plus three crafted redirects.
  Every 8197-byte `new_path` had **no live allocation at `new_path+8208` at
  the moment it was allocated** (`live_at_alloc=0,0,0,0`); that neighbour is
  allocated only later on the response path. The warm request's freed 8 KB
  chunk is consumed by the next request's 9003-byte request buffer, so the
  crafted `new_path` comes from top again. With a 38-byte query the first
  crafted request already aborts the allocator, consistent with the
  availability-only ceiling.

Self-checking replay from a clean archive:
`cd lab/frontier/civetweb2shell && bash run-natural.sh /tmp/cw-natural` →
11 PASS / 0 FAIL, rc 0; trace sha256
`15ce7bdba90a3f060304b584928f5c79974ff6b22b22944c23879b81b189ae8a`.
This is a negative result; it does not upgrade the rung.

## Preserved negatives

- Public PoC 404s in this docroot; the slash-collapsing request is locally
  derived. Long query + short path does not overflow (`:15251` budgets it).
- Short slash run is a 301 with no corruption (negative control in `run.sh`).
- Natural adjacency was measured absent in the unmodified build (probe
  above); no pointer control or execution was observed. CISA's
  published CVSS vector is availability-only; the CVE's CWE-121 (stack) label
  is inconsistent with the heap allocation.
