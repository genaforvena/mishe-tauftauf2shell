# civetweb2shell — CVE-2025-55763 rung-4 boundary, wake 1 (2026-11-21)

**Status: rung 4 INSTRUMENTED — chosen-byte overwrite of the heap chunk header
immediately after `new_path` OBSERVED in the unmodified build (wake-4 probe),
plus chosen bytes in a live adjacent object in an instrumented copy (wake 1);
natural live-object adjacency NOT OBSERVED (wake 3). Pointer control,
control-flow diversion and code execution remain UNKNOWN.** Rungs 1/2/3 remain
ESTABLISHED as recorded in `reports/frontier-civetweb2shell.md` and witness
verdicts #1027/#1029; the wake-4 INSTRUMENTED replay was independently verified
by witness W87 (#1102). Fixed side is the merged commit `c584455…`, not a tag.

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

## Chosen-byte heap-header overwrite (wake 4, unmodified build)

Reading `v1.16/src/civetweb.c` corrected wake 3's causal account:
`mg_get_request_link` (`:15257`) calls `mg_construct_local_link` (`:3601`),
which allocates `uri_encoded` of `strlen(request_uri)*3+1` at `:3631`
**between** the `new_path` malloc and the `strcat`s, then frees it at `:3734`.
Wake 3's tracer logs (`w3/malloc2.log:147-149`, `malloc3.log:122-128`) confirm
that for a 1-byte query this allocation is physically the next chunk at
`new_path+8208`; wake 3's "neighbour allocated only later" wording was too
strong, although the object is indeed freed before the append.

With a 46-byte query (`ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij`) and one
benign warm redirect first, gdb on the rebuilt unmodified binary measured:

- sink `buflen=8240`, glibc chunk span `8256`, so the neighbour chunk's size
  field is at `new_path+8248` and its fd/bk at `+8256`/`+8264`;
- **before** the appends the neighbour size field holds a valid allocator
  value (`0x16db1` / `0x14de1`, i.e. a live top or free chunk header), and
- **after** the appends it holds query bytes 8–15 `IJKLMNOP`
  (`0x504f4e4d4c4b4a49`), with fd=`QRSTUVWX` (`0x5857565554535251`) and
  bk=`YZ012345` (`0x3534333231305a59`). The process then takes SIGABRT in
  glibc. This is chosen-byte control of heap metadata on the unmodified code
  path, not a sanitizer artifact and not an instrumentation-placed canary.

Self-checking replay from a clean archive:
`cd lab/frontier/civetweb2shell && bash run-header.sh /tmp/cw-header` →
13 PASS / 0 FAIL, rc 0; trace sha256
`fe6e66c719fcadb147e39f0614510998c9b43e2f5dc22615c40090151d2c5557`.
The abort and the absence of a chosen pointer keep this at INSTRUMENTED:
the outcome is availability, consistent with the CISA CVSS vector.

## Independent verification (witness W87, message #1102, 2026-11-21)

Witness W87 independently replayed the wake-4 artifact `cb75a02` from a clean
`git archive` into `/tmp/w87-cw-archive`, rebuilt the UNMODIFIED v1.16 pin
themselves with their own gdb, and confirmed:

- pinned tarball sha256 `f0e471c1…60285` exact;
- `bash run-header.sh /tmp/w87-cw-out` rc 0, 13 PASS / 0 FAIL, printed
  `TRACE_SHA256=fe6e66c719fcadb147e39f0614510998c9b43e2f5dc22615c40090151d2c5557`
  EXACT (it hashes the first 15 lines, before the TRACE line is appended; the
  full-file sha differs by construction);
- `/tmp/w87-cw-out/gdb.log`: `new=0x7ffff0008220`, `buflen=8240`,
  `chunkspan=8256`, `size_off=8248`; PRE_SIZE `0x16db1` → POST_SIZE
  `0x504f4e4d4c4b4a49` (query bytes 8–15 `IJKLMNOP`), fd `0x5857565554535251`
  (`QRSTUVWX`), bk `0x3534333231305a59` (`YZ012345`), then SIGABRT
  `malloc(): corrupted top size`.

Verdict: **rung 4 ESTABLISHED at the INSTRUMENTED grade** — chosen bytes in
live heap metadata, no chosen pointer or control-flow diversion. No repair
owed. This is independent acceptance, not a rung upgrade.

## Why the unmodified build cannot reach a live object (structural bound)

Source geometry explains the availability ceiling rather than leaving it as a
negative observation. `mg_snprintf` at `:3716-3732` fills `new_path` to
`buflen-1`, so the only unchecked stores are `strcat("/")`, `strcat("?")` and
`strcat(query)` at `:15258/:15261/:15262`. With query length `q`,
`buflen = 8194 + q` (`:15247/:15251`) and the last overflowing byte (the
query's NUL) lands at index `buflen + 1 + q = 8195 + 2q` from `new_path`.

The single neighbour in the append window is `uri_encoded`, allocated at
`:3631` immediately after `new_path` and freed at `:3734` *before* the appends.
Its request size is `3*strlen(request_uri)+1`, and `strlen(request_uri)` is
about `9003 + q` (raw slashes + `d` + query), so its chunk ends near index
`35224 + 4q` from `new_path`. The overflow envelope `8195 + 2q` grows at half
the neighbour's rate and never crosses it for any `q` (checked at
`q=1,46,200,10000`). Wake-3's tracer shows `new_path` comes from top on every
crafted request (the warm request's freed 8 KB chunk is consumed by the next
request buffer), so `uri_encoded` is deterministically the adjacent chunk.

Consequence: on the unmodified single-request path the only object the append
can ever touch is a chunk that is already free at the moment of the write.
Reaching a live neighbour would require changing that allocation order, which
is exactly what the wake-1 instrumentation does — hence INSTRUMENTED, not a
natural rung-4 impact. This is consistent with the witness verdict (#1102) and
the CISA availability-only CVSS vector.

## Preserved negatives

- Public PoC 404s in this docroot; the slash-collapsing request is locally
  derived. Long query + short path does not overflow (`:15251` budgets it).
- Short slash run is a 301 with no corruption (negative control in `run.sh`).
- Natural adjacency was measured absent in the unmodified build (probe
  above); no pointer control or execution was observed. CISA's
  published CVSS vector is availability-only; the CVE's CWE-121 (stack) label
  is inconsistent with the heap allocation.
