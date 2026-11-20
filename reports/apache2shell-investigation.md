# Apache2Root investigation — CVE-2026-119618 / GHSA-34m4-m9fh-gqp5

Voice: `apache2shell`. Status 2026-11-20 15:50Z: **rung 3 confirmed** (reproducible
differential crash + corrupted pool metadata observed under gdb). Rung 4 NOT
reached: no Stage A canary, no chosen-offset write, no pointer control.
Everything below was produced inside this plant's loopback lab; external
claims are labeled as claims.

## Rung 1 — suspected (source-bound, verified locally)

Affected: httpd **2.4.55–2.4.70**, standalone mod_h2 **2.0.8–2.0.42**; fixed in
**2.4.71**. Upstream fix `apache/httpd@824beab` ("mod_http2: assign_headers
update table"), one line in `modules/http2/h2_request.c`:

```
-    apr_table_setn(req->headers, "Content-Length", "0");
+    apr_table_setn(r->headers_in, "Content-Length", "0");
```

Verified in both source trees at `h2_request.c:352-358`: when a request has
`Content-Type` but no `Content-Length` and END_STREAM was already seen
(`no_body`), 2.4.70 writes `Content-Length: 0` into `req->headers`, the header
table of the HTTP/2 **stream**, whose pool is owned by the c1 connection thread.
2.4.71 writes into the private `r->headers_in` of the request instead. Vendor
advisory prose (CWE-362, "worker thread writes into memory owned by the
connection thread through a shared lock-free allocator", pre-auth, claimed RCE
on a default mod_http2 configuration) is a **claim**, not independently
reproduced here.

## Rung 2 — deterministic state differential (reproduced 15:03Z)

`lab/frontier/apache2root/oracle.sh` on the inherited ASan/UBSan builds, h2c
`GET /cgi-bin/oracle`, `Content-Type: text/plain`, body-less with END_STREAM:

- 2.4.70 (`127.0.0.1:7080`): `CONTENT_LENGTH=[<UNSET>]`, `CONTENT_TYPE=[text/plain]`
- 2.4.71 (`127.0.0.1:7171`): `CONTENT_LENGTH=[0]`, `CONTENT_TYPE=[text/plain]`

Both HTTP/2 200, no ASan report. The buggy write is observable before any
corruption.

## Rung 3 — reproducible crash, then confirmed corruption

### Trigger shape

Raw h2c frames (`lab/apache2shell/h2client.py`), body-less POST with
`Content-Type: application/x-www-form-urlencoded`, no `Content-Length`,
END_STREAM on the HEADERS frame. The header table is filled to an APR capacity
boundary with 78 `x-pad-NNN: v` entries (`drive.py --shape full --fill 78`);
`apr_table_make(pool, 10)` doubles 10→20→40→80→160, so the buggy
`apr_table_setn` lands on a reallocation/capacity boundary. Driver: 8
connections × 100 streams, 15–20 s per run.

### Differential child crashes (both affected and fixed build, identical traffic)

| time (UTC) | build | port | LogLevel | drive result | child SIGSEGV |
|---|---|---|---|---|---|
| 15:21:04 | 2.4.70 | 7181 | http2:trace3 | sent=11730 responses=23264 | **3** |
| 15:21:20 | 2.4.71 | 7182 | http2:trace3 | sent=29177 responses=58356 | **0** |
| 15:23:30 | 2.4.70 | 7183 | info | sent=5400 responses=9984 | **3** |
| 15:23:35 | 2.4.71 | 7184 | info | sent=20500 responses=40132 | **0** |

The crash is not a logging artifact: it reproduces at `LogLevel info`, and the
fixed build survives ~2.5× the traffic. Crash is probabilistic per stream (a
few child deaths per ~15–20 s sweep), not one request = one crash. The 15:21
error logs (304 MB + 762 MB, trace3) are preserved as evidence under
`lab/apache2shell/logs/`; later runs use `info`.

### Which code faults (gdb, loopback only)

`lab/apache2shell/gdb-inspect.sh` runs 2.4.70 under gdb with
`handle_segv=0` (Apache's `ap_fatal_signal_setup` otherwise replaces ASan's
SIGSEGV handler) and dumps the faulting state. Three fault sites were captured
across three captures, all on the **c1 event-MPM connection thread**:

1. `logs/2.4.70-gdb-p7185-f78-152451.gdb.log:75-95`: `apr_allocator_free+23`
   in **system** `/lib/x86_64-linux-gnu/libapr-1.so.0`, called from
   `c1_in_feed_brigade` (`h2_c1_io.c:467`) → `h2_c1_read` → `h2_session_process`.
2. `logs/2.4.70-gdb-p7190-f78-154548.gdb.log:67-82`: `apr_pool_destroy+32`,
   recursively, called from `h2_stream_destroy` (`h2_stream.c:641`,
   `apr_pool_destroy(stream->pool)`) → `c1_purge_streams`
   (`h2_mplx.c:654`) → `h2_session_process`.
3. `logs/2.4.70-gdb-p7192-f78-155456.gdb.log`: `apr_allocator_free`, from
   `ap_core_input_filter` (`core_filters.c:281`) → `read_and_feed`
   (`h2_c1_io.c:480`) → `on_stream_input` (`h2_session.c:1398`).

The second capture is the memory-state proof. Disassembly:

```
apr_pool_destroy+15: mov 0x70(%rdi),%rax    ; rax = pool->child
apr_pool_destroy+32: mov (%rax),%rdx        ; FAULT (rax is not a pointer)
```

At the fault `rax = 0x73580d5041` — ASCII bytes `41 50 0d 58 73` ("AP\rXs"),
not a canonical pointer. The dumped pool at `0x7fffd4b87418` shows a repeating
non-pointer pattern at 16-byte stride, interleaved with still-valid pointers:

```
0x7fffd4b87428: 0x00000000580d5041   0x00007fffd4bd5530
0x7fffd4b87438: 0x00007fffd4bd5540   0x20303220580d5041
0x7fffd4b87458: 0x00000054580d5041   0x00007fffd4bd5560
0x7fffd4b87468: 0x00007fffd4bd5570   0x35633434580d5041
0x7fffd4b87488: 0x00000073580d5041   0x00007fffd4bd5590   <- pool->child (+0x70)
```

A valid `apr_pool_t.child` is NULL or a pointer to a child pool; it cannot hold
`0x73580d5041`. This is **observed memory corruption by debugger inspection**,
not just a crash. The exact provenance of the ASCII bytes is not yet pinned to
a particular header field; do not claim chosen-byte placement from this alone.

### Causal reading (limits stated)

2.4.70's c2 worker writes into the c1-owned stream table/pool; c1 later frees
that pool in `h2_stream_destroy`, or frees a brigade through the same shared
allocator. The 15:21 trace3 log also contains many
`h2_mplx.c(188): ... cleanup, c2 is running, abort` lines, consistent with c1
cleanup while c2 still holds the pool. 2.4.71's one-line fix removes the
cross-thread write and the differential disappears. The precise interleaving
(a torn `apr_table_setn` realloc vs. `apr_pool_destroy`, or a stale pool pointer
after abort) is **still open**; both fault sites are downstream symptoms.

### Negative results preserved

- ASan stayed silent in every non-gdb sweep despite instrumented `httpd` and
  `mod_http2.so`. Cause: the fault is in uninstrumented system libapr and
  Apache installs its own SIGSEGV handler. Absence of an ASan report is NOT
  absence of corruption; it is a detector gap.
- A forced-ASan sweep at 15:50Z (`sweep-asanforce.sh`, `handle_segv=1:allow_user_segv_handler=0:verbosity=1`) was **invalid**: `AH02324: A resource shortage or other unrecoverable failure was encountered before any child process initialized successfully`, then `RuntimeError: can't start new thread`. No ASan report, no crash evidence: `verbosity=1` FakeStack allocation (11 MB per thread across the worker pool) exhausted the host. Its hung httpd tree was terminated; keep this as a negative, and do not reuse `verbosity=1`.
- The 15:45Z gdb capture left its httpd parent and four children orphaned because `gdb-inspect.sh` killed gdb but not the httpd PidFile tree; they were terminated at 15:53Z. The script now kills the PidFile tree on exit. Orphans inflate thread counts and cause the fork failures above, so always check `pgrep httpd` between runs.
- Two runs at 15:25 (matched gdb on 2.4.71 and an f16 sweep) are **invalid**:
  `vfork: Resource temporarily unavailable`, `ap_thread_create: unable to
  create worker thread`, `fork: Unable to fork new process` from overlapping
  experiments. No httpd/gdb/drive.py processes remained afterward.
- Frontier's earlier 3×200×65-header trace4 sweep found no crash; it is
  preserved as a negative, not erased. The capacity-boundary fill (78) is the
  change that exposed the race.

## Rung 4 — not reached

Per `docs/task.md`, rung 4 needs Stage A placement control (chosen bytes at a
chosen offset via canary), Stage B wire-pure trigger, Stage C pointer control /
benign marker execution. None is demonstrated. The public PoC's prefork-MPM
setup differs from these event-MPM lab builds; reliability claims from that
repository remain claims. Next wake: attempt Stage A on the affected build
only, keeping the fixed-build differential as the control.

## Reproduction (from a clean checkout, loopback only)

```
cd lab/apache2shell
./sweep.sh 2.4.70 <port> full 78 8 100 20 info     # affected: expect child SIGSEGV
./sweep.sh 2.4.71 <port> full 78 8 100 20 info     # fixed: expect none
./gdb-inspect.sh 2.4.70 <port> 78 20               # gdb fault + memory dump
```

`oracle.sh` in `lab/frontier/apache2root/` reproduces rung 2. Runtime state
(`logs/`, `run/`) is gitignored; only scripts and this report are committed.

`drive.py`, `sweep.sh`, `gdb-inspect.sh` are this plant's harnesses. `h2client.py` and `ref-poc.py` were fetched 2026-11-20 from `github.com/googlesky/CVE-2026-119618` (`poc/h2.py`, `poc/poc.py`) as unmodified reference inputs; claims about that repository remain claims. `race-boundary.sh` (partial, cut mid-sweep) and `sweep-asanforce.sh` (invalid, resource-shortage run) are preserved negatives, not canonical drivers.
