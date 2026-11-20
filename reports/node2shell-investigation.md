# Node2Shell investigation — CVE-2026-123828

One-byte heap overflow in Node.js HTTP/2 `session.altsvc()` handling
(`src/node_http2.cc`). Target admitted 2026-11-20 (operator, standing
approval #6, similar-things mandate). This report records every rung as
observed; unknowns stay unknown.

## Ground truth (verified 2026-11-20, first wake of node2shell)

All claims below were re-derived from primary sources, not taken from
Snyk or prior walls:

- **Fix commit** `nodejs/node@ae9ab37d62` — "http2: avoid overflowing
  ALTSVC buffers" (Matteo Collina, GPG-verified; PR nodejs-private#1035;
  CVE-ID in message). The diff removes `String::WriteFlags::kNullTerminate`
  from both `WriteOneByteV2` calls in `Http2Session::AltSvc`
  (`src/node_http2.cc`), because `nghttp2_submit_altsvc()` consumes
  explicit lengths. Upstream's own regression test uses a 1048-char
  origin and a 1050-char alt value.
- **Allocation** (`src/util.h` / `src/util-inl.h`): `MaybeStackBuffer<T>`
  default stack storage is 1024 items; `AllocateSufficientStorage(len)`
  `Realloc`s exactly `len` bytes — no `+1`. Heap path requires
  `len > 1024`.
- **Termination write**: 24.x/26.x pass `kNullTerminate` explicitly;
  ≤22.x call V1 `WriteOneByte(isolate, *origin)` whose V8 default
  (`length == -1`, `NO_OPTIONS`) writes `buffer[write_length] = '\0'`
  (V8 `WriteHelper`, present unchanged in v22.23.5's vendored V8).
- **Tagged-source differential** (fetched and diffed): `v24.22.2` and
  `v26.13.0` carry the vulnerable code; `v24.22.3` and `v26.13.1`
  carry the fix verbatim.
- **Official advisory** (nodejs.org November 2026 security releases):
  remote unauthenticated heap-buffer-overflow "with a long origin",
  app passes "attacker-controlled value such as a request's :authority"
  to `Http2Session.altsvc()`; affects active release lines 24.x, 26.x;
  reported by zonduu.

### 22.x discrepancy (resolved)

Snyk claims 22.x < 22.23.5 fixed in 22.23.5. Tagged sources contradict
the "fixed" half: `v22.23.4` and `v22.23.5` `node_http2.cc` are
byte-identical in the AltSvc function (old V1 call, no backport), and
v22.23.5's vendored V8 still null-terminates. So 22.x through 22.23.5
still carries the same OOB write **as a rung-0 source-read claim**
(not reproduced on a 22.x build yet; the official advisory does not
list 22.x). Host stock `v20.20.2` (EOL line) has the identical V1
pattern — read from the `v20.20.2` tag.

## Trigger shape

```
origin = 'https://' + request[':authority']      // app-forward pattern
stream.session.altsvc(alt, origin)               // id=0, origin non-empty
```

- Heap-backed when `origin_len > 1024`; C++ CHECK caps
  `origin_len + value_len <= 16382`. Attacker controls the exact
  allocation size (1025..~16370) via authority length
  (`origin_len = 8 + authority_len`) and the pre-overflow content.
- The value buffer overflows too if the app's alt string exceeds 1024 —
  realistic only when the attacker controls the alt value; primary
  remote vector is the origin buffer.
- **glibc placement class**: `origin_len ≡ 8 (mod 16)` ⇒
  `request2size = origin_len + 8` ⇒ `malloc_usable_size == origin_len` ⇒
  the NUL lands exactly on the **size-field LSB of the following chunk**
  (poison-NUL-byte primitive, same class as Ruby2Shell). Other residues
  land in intra-chunk slack or the next chunk's unused `prev_size` —
  no immediate effect.

## Evidence ladder

- **Rung 0** — suspected: advisory + fix-diff read as specification
  (above).
- **Rung 2/3-class observation on stock glibc (not deterministic)** —
  first wake, 2026-11-20: stock prebuilt `node v20.20.2` (official
  binary, production glibc of this host), loopback-only, single
  unauthenticated request with `authority_len = 1040`
  (`origin_len = 1048 ≡ 8 mod 16`): server died `SIGABRT (rc=134)` with

  ```
  malloc(): mismatching next->prev_size (unsorted)
  ```

  glibc's own heap-integrity detector fired — the OOB NUL had cleared
  the size LSB of a free unsorted chunk. Observed **1/6** identical
  runs; a following 45-run sweep over `origin_len` 1024..1112 produced
  no further aborts (natural rate ≈2%, layout-dependent). Real
  corruption observed on a stock build, but not a reproducible-crystal
  rung-2 result until determinism is groomed. Version honesty: v20.20.2
  is an EOL line carrying the same code; the officially listed affected
  lines are 24.x/26.x, which get the Valgrind differential below.
- **Rung 2 — deterministic, differential (2026-11-20, second wake)**:
  official prebuilt binaries under Valgrind 3.22.0 (host), loopback-only,
  same harness, one unauthenticated request, `authority_len=1040`
  (`origin_len=1048`):

  - `v24.22.2` (affected): client received the ALTSVC echo
    (`origin_len=1048 stream=0` — full trigger path executed), and
    Memcheck reported **`Invalid write of size 1`** with the exact
    causal stack — **2/2 identical runs**:

    ```
    Invalid write of size 1
      at v8::String::WriteOneByteV2(...) const
      by node::http2::Http2Session::AltSvc(v8::FunctionCallbackInfo<v8::Value> const&)
      by Builtins_CallApiCallbackGeneric
    ERROR SUMMARY: 1 errors from 1 contexts
    ```

  - `v24.22.3` (fixed, same request, ALTSVC echo received):
    `ERROR SUMMARY: 0 errors from 0 contexts` — no invalid write.

  This upgrades the observation to a reproducible, deterministic
  one-byte heap OOB write in the vulnerable function on the officially
  affected line, with the fixed release as a clean control. Logs:
  `lab/node2shell/tmp/vg-v24.22.2.log` (gitignored bulk; quoted here).
  (Memcheck observes the write wherever it lands, so this rung does not
  need the `len ≡ 8 mod 16` placement class — that matters for Stage A
  on production glibc.)

  Negative result preserved: the first wake's multi-wake ASan source
  build was killed at the wake boundary (`make: Terminated`, SIGTERM
  — the engine reaps detached jobs), and is abandoned; Valgrind on
  official prebuilts delivers the same differential without any build.

## Stage A — deterministic one-byte size-shrink and at-will abort (third wake, 2026-11-20)

The 1/6 luck on stock v20.20.2 was layout luck of that EOL binary's
startup heap. On the **officially affected prebuilt `v24.22.2`** the
same single unauthenticated request (loopback, `authority_len = 1040`,
`origin_len = 1048 ≡ 8 mod 16`) aborts the server **at will, on the
first request** — no grooming needed, the binary's own per-request
allocation window is enough:

- **10/10 identical runs** (fresh process each): server SIGABRT
  rc=134, `malloc(): invalid size (unsorted)`; client killed by
  ECONNRESET before any response. Committed script
  `lab/repro/node2shell-stageA.sh` (5-run smoke: 5/5, off-class and
  fixed controls clean).
- **Attacker-chosen length chooses the effect** (bare prebuilt, one
  request per fresh process): every tested on-class length in
  1048..1960 aborted — `origin_len` 1048, 1064, 1096, 1160, 1256,
  1384, 1544, 1736, 1960 → **9/9 aborts**; every tested off-class
  length completed normally — 1040, 1041, 1047, 1049, 1056, 1057,
  1072, 1073, 1088 → **0/9 aborts**. Fourth wake completed the map
  upward: on-class lengths 2216, 2504, 3560, 5416, 9896, 14984 →
  **0/6 aborts — the request is served and the server stays alive**.
  So the deterministic abort window is origin_len 1048..1960 only;
  for larger on-class lengths the NUL still lands on a size-field LSB
  (the placement class is size-independent), but no validator fires
  inside the request — the victim there is either flag-only-aligned or
  **in use at write time**, which is exactly the persistent-corruption
  regime the rung-4 path needs. Debugger-walking a completing
  large-length run is the open next step.
- **Fixed control, same request shape**: prebuilt `v24.22.3`, on-class
  lengths 1048, 1064, 1096, 1256, 1544, 1960, 2504, 3560, 5416, 9896
  → **0/10 aborts**, every request completed. The deterministic
  differential now holds on production glibc, not just under Memcheck.

### Rung 3 — confirmed corruption, debugger-observed bytes

`gdb` (15.1, ASLR off) on the bare aborting configuration
(v24.22.2 prebuilt, breakpoint at `nghttp2_submit_altsvc` — reached
after the OOB write, before the frame copies):

```
ORIGIN ptr=0x6e45b70 len=1048
origin chunk hdr: 0x6e45b60:  0x0  0x421       ← exact-fit 0x420 chunk
victim chunk at 0x6e45f80:
  0x6e45f80:  0x6161616161616161  0x700        ← prev_size holds the
                                                 attacker's 'aaaa' (tail
                                                 of the origin string);
                                                 size field NULed:
                                                 0x701 → 0x700
malloc(): invalid next size (unsorted)
```

Continuing hits SIGABRT with the full causal stack — the abort is the
very next malloc **inside the same `session.altsvc()` call**:

```
#6  malloc_printerr "malloc(): invalid next size (unsorted)"
#7  _int_malloc (main_arena, bytes=1076)
#9  node::mem::NgLibMemoryManager<...>::MallocImpl
#10 nghttp2_submit_altsvc ()
#11 node::http2::Http2Session::AltSvc(...)
```

Observed chain on production glibc, stock official binary, one
unauthenticated request: the NUL lands on the size-field LSB of the
free chunk following the origin buffer, and nghttp2's ALTSVC
origin-copy malloc (1076 bytes) fails glibc's unsorted-bin validation
and the process dies.

### Rung 3 mechanism — corrected (fourth wake, 2026-11-20 10:25Z)

The stage-A wake recorded the corruption as a flags-only
PREV_INUSE-clear ("0x701 → 0x700"). That inference was wrong: the
post-write sizefield alone cannot distinguish real size 0x700 (flags
only) from 0x720 (magnitude in the low byte). gdb 15.1 with libc debug
symbols plus the committed mtrace preload in the same inferior (three
independent aborting runs, ASLR off) settles it:

- The origin buffer O is served by **splitting a consolidated free
  donor** (the per-request AltSvc temporaries: two origin_len+1 copies
  and a 2049-byte buffer, plus session-cycle buffers), leaving a free
  **split remainder R directly after O** in the unsorted bin.
- The NUL zeroes R's size-field low **byte** — and R's real size
  carries magnitude in that byte. Observed victims: real 0x820 →
  believed 0x800 (sizefield 0x821→0x800), 0x910 → 0x900, 0xd20 →
  0xd00; a further run aborted with `malloc(): invalid size (unsorted)`
  (victim small enough that the zeroed byte collapses the size).
  A NUL on this host's glibc is therefore a **size-magnitude shrink of
  0x10..0xf0** — the same primitive class as Ruby2Shell's 0x53 bump,
  not a flag clear.
- Consequence: the next unsorted scan (the 1076-byte malloc inside
  the same `nghttp2_submit_altsvc` call) computes R's "next chunk" at
  `R + shrunk_size` — 0x10..0xf0 bytes **inside R's real extent** —
  and reads zeroed sbrk slack (or 'aaaa' residue) as the next chunk's
  size: `malloc(): invalid next size (unsorted)` at malloc.c:4081,
  SIGABRT. Bytes observed (gdb walk, committed
  `lab/repro/node2shell-shrinkwalk/`): victim 0x6e3ea00 sizefield 0x900,
  real extent 0x910 with a consistent foot, chunk at 0x6e3f300 (the
  corrupted next) reads `0x0 0x0`.

So every deterministic abort so far is the unsorted-bin validator
acting inside the same request — DoS. For impact beyond DoS the write
must reach a chunk that is **in use** at write time (no scan sees it)
and is freed later with the shrunken size — that produces a free chunk
whose believed extent ends inside its real extent: the overlap
primitive (same family as Ruby2Shell's rung-4 unsorted-bin overlap).
The attacker steers the donor composition (and hence R's size class)
via origin_len and request sequencing; an exact-fit 0x420 hole with an
in-use right neighbor is the rung-4 target layout.

Open sub-case, honestly recorded: in the mtrace env with the
multi-request client harness, the on-class request **completed** 4/4
(fresh processes, ASLR off, but with run-to-run differing heap
placements — connection timing shifts the inventory even with ASLR
off), while the single-shot rung-1 client aborts 10/10 bare. In the
one fully-traced completing run the victim R had real size 0xc50,
which by the shrink model should also have tripped the scan (believed
0xc00, next reads 'aaaa' residue); it did not, and the believed-size
state in completing runs was not debugger-observed. Unknowns stay
unknown; the completing regime is real (4/4 observed) but its heap
state at the write is not yet walked.

## Reproduction

Stock-glibc abort observation (natural rate ≈2%):

```
# terminal 1
node lab/repro/node2shell-rung1-server.js 0
# terminal 2 (port from server's LISTEN line; repeat runs for the ~2% class)
node lab/repro/node2shell-rung1-client.js <port> 1040
```

Deterministic at-will abort (Stage A, rung 3; ~8 s for 5 runs + both
controls):

```
sh lab/repro/node2shell-stageA.sh 5
# → 5/5 rc=134 on v24.22.2; off-class and v24.22.3 controls stay alive
```

Deterministic Valgrind differential (rung 2; ~15 s per run):

```
# official prebuilts from nodejs.org/dist — v24.22.2 (affected), v24.22.3 (fixed)
valgrind --tool=memcheck --log-file=vg-affected.log \
  path/to/node-v24.22.2-linux-x64/bin/node \
  lab/repro/node2shell-rung1-server.js 0 &      # reads LISTEN <port> from stdout
node lab/repro/node2shell-rung1-client.js <port> 1040
# then kill the valgrind server; vg-affected.log has the Invalid write
# of size 1 (WriteOneByteV2 <- Http2Session::AltSvc); repeating with
# node-v24.22.3 gives ERROR SUMMARY: 0.
```

Harness: `lab/repro/node2shell-rung1-server.js` (HTTP/2 server on
127.0.0.1 forwarding `:authority` into `session.altsvc` — the advisory's
app precondition), `lab/repro/node2shell-rung1-client.js` (single
request, syntactically valid long authority, waits for the ALTSVC
frame echo proving the full path executed) and
`lab/repro/node2shell-stageA.sh` (rung-3 runner with off-class and
fixed-release controls; `VULN_BIN`/`FIXED_BIN` env override the node
binaries). All committed.

## Lab provenance

- First wake: nodejs.org source tarball `node-v24.22.2.tar.gz` (117 MB);
  `apt-get install clang` → clang 18.1.3 (08:46Z); tagged-source
  fetches from raw.githubusercontent (provisioning, no probing).
  ASan build attempt abandoned (killed at wake boundary; see negative
  result above).
- Second wake (2026-11-20 08:56Z): nodejs.org prebuilt
  `node-v24.22.2-linux-x64.tar.xz` and `node-v24.22.3-linux-x64.tar.xz`
  (sha256 recorded below); Valgrind 3.22.0 already present on host.

  ```
  48cc0e21e048790e54c0cf5749c2725005313d652651c40b7a21feb9697aaf75  node-v24.22.2-linux-x64.tar.xz
  4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb  node-v24.22.3-linux-x64.tar.xz
  ```
