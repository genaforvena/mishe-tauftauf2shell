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
  1072, 1073, 1088 → **0/9 aborts**. So in the bare single-shot
  harness the deterministic abort window is origin_len 1048..1960.
  Fourth wake completed the map upward: on-class lengths 2216,
  2504, 3560, 5416, 9896, 14984 → **0/6 aborts in the bare
  single-shot harness**. Fifth wake correction: that "completing
  regime" is **layout-chosen, not length-chosen** — under the
  debugger at origin 2216 the same request aborts in 5/9 fresh
  walks (free-remainder victim, identical validator), and in the
  other 4/9 the NUL lands on the **top chunk's sizefield** and the
  run persists (next subsection). Length only buys the placement
  class; the victim is whatever the layout puts after O.
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
which by the shrink model should also have tripped the scan; it did
not, and that mtrace-env victim remains unexplained (its believed
size state was never debugger-walked). The bare-harness completing
regime **is** now walked — next subsection — but that 0xc50
observation belongs to a different env and stays open.

### Rung 3.5 — completing regime walked: the victim is the top chunk (fifth wake, 2026-11-20 10:15Z)

Parametrizing the committed shrinkwalk (`LEN` env, default
authority 2208 → origin 2216 ≡ 8 mod 16) and walking fresh gdb
processes at the same completing length settles what the bare
harness's 0/6-aborts really was:

- **5/10 walks aborted** with the free-remainder victim of the
  corrected mechanism (believed 0x800/0x5700, next chunk read in
  zeroed slack → `malloc(): invalid next size (unsorted)`). The
  "no validator fires at ≥2216" reading of the bare length map was
  an artifact: under the debugger the same length aborts half the
  time. Whether a given run aborts is decided by **what chunk
  follows O**, i.e. by layout, not by length.
- **4/10 walks hit the top chunk**: O is carved from top, so the
  NUL lands on **top's sizefield LSB**. Measured against brk
  (glibc keeps top_end == brk): real top size 0x56910 → believed
  0x56900 (shrink 0x10), 0x56520 → 0x56500 (0x20), 0x57b70 →
  0x57b00 (0x70), 0x56c10 → 0x56c00 (0x10) — **persistent
  size-magnitude shrink of a live top sizefield, no validator
  inside the request**. One further run was **flag-only** (real
  0x56300 == believed: the NUL cleared top's PREV_INUSE bit only).
- **Serve proof**: the flag-only run completed end-to-end under
  the debugger — the client received the ALTSVC echo
  (`client: ALTSVC origin_len=2216`), the server stayed alive the
  full observation window. A shrink-flavor run (shrink 0x10)
  likewise served: exactly one breakpoint hit, no client retries,
  gdb idle to timeout. The earlier fourth-wake belief that the
  2216 regime "completes 0/6" is thus explained and upgraded:
  those runs completed **with top's sizefield persistently
  corrupted**.
- **Instrumentation lesson (negative result, kept)**: the first
  four top-victim walks were misread as clean completions; the
  then-current walk.py walked off the believed top extent into
  unmapped memory at brk (`gdb.MemoryError at 0x6ea8000`), which
  killed the inferior before serving. The walk now branches on
  `victim == top`, measures the shrink via `sbrk(0)`, and skips
  the unsorted walk; `run.sh` captures the client's completion
  line.

Ladder read: this is persistent, debugger-observed corruption of a
live heap structure surviving past the request (rung 3, persistent
variant). It is not yet impact: a ≤0xf0 top-size shrink routes the
next sysmalloc extension down the non-contiguous path (old top
freed at believed size, ≤0xf0 leaked; no overlap), and a cleared
PREV_INUSE on top only arms a backward-consolidation abort/
overlap if the predecessor chunk is later freed with a controlled
prev_size. The rung-4 path remains the **in-use allocated victim**:
groom the heap so the chunk following O is a live allocation at
write time (multi-request hole grooming; persistent per-connection
allocations — e.g. HPACK dynamic-table entries — are the candidate
right-neighbor D), so its shrunk sizefield survives to its own free
and manufactures the believed-extent-inside-real-extent overlap
(Ruby2Shell rung-4 family).

### Rung-4 step 1 — multi-request hole inventory; harmless-residue classes confirmed (sixth wake, 2026-11-20 10:33Z)

Committed harness additions (`lab/repro/node2shell-shrinkwalk/`):
`multi-client.js` (two requests on ONE http2 session, LEN/LEN2
parametrization), `run-multi.sh`, and `multi_walk()` in `walk.py`
(hit 1 records O1; hit 2 inventories the freed O1 hole, classifies
O2's victim — a free-unsorted victim is tagged by fd==bk==arena
sentinel; IN-USE is only claimed when the believed-next address holds
a sane chunk header, after content-as-header misreads bit us).
Loopback only, ASLR off, fresh gdb process per run. Raw logs
gitignored under `lab/node2shell/tmp/w6/`.

**Byte-level confirmation of the residue classes** (previously a
source-read prediction): at `origin_len = 3632 ≡ 0 (mod 16)` the
walk shows the following chunk's **prev_size low byte NULed while its
sizefield stays intact** — 4/4 walks `prev_size 0x6d43000 /
0x6d42500 / 0x0 / 0x6e54000, sizefield 0x11c1` — and the request
**completed 6/6** (top or free chunk after O alike): the write lands
on `o+0x10+len`, which for `len ≡ 0 (mod 16)` is the next chunk's
prev_size (unused while the predecessor is in use, rewritten by
free()'s set_foot), and for `len ≡ 9..15 (mod 16)` never leaves the
origin allocation. `walk.py` now prints `NUL-CLASS` per hit, derived
from `len`: only `origin_len ≡ 8 (mod 16)` is corrupting. This also
retro-explains the off-class 0/9-abort map of stage A.

**Inventory result (honest negative for the in-use victim)**: in the
same-session two-request flow the chunk following request 2's O2 is
**always a free unsorted remainder**, never an in-use allocation:

- LEN=2208 both requests (4 completing-then-hit-2 runs): O2 lands at
  O1's old address (the freed region re-serves as donor), and the
  following chunk is a free unsorted remainder with real size 0x810 →
  believed 0x800 (`sizefield 0x811→0x800`, fd=bk=sentinel) → the
  in-call `malloc(origin+28)` validator aborts
  (`invalid next size (unsorted)`). One layout variant left the donor
  unsplit (0x1180 = O1 0x8b0 + copy 0x8d0) with an **in-use 0xbf0
  chunk right after it** — the golden adjacency exists in this
  pipeline — but O2 (0x8b0) front-splits the donor instead of
  exact-fitting it.
- A second flavor: a small free unsorted victim whose whole
  sizefield was ≤0xff (`sizefield 0x0` post-write) →
  `malloc(): invalid size (unsorted)`, same call site. Both validator
  flavors now observed at hit 2.
- Exact-fit attempts (LEN2 sized so O2's chunk equals the observed
  donor: authority 4464 → origin 4472 → chunk 0x1180, and donor
  0x10c0 variant): request 2's own header-block decode **consumes the
  donor first** — a 0xb10 in-use chunk (nghttp2 hd-inflate storage)
  sits at O1's old address at hit 2, O2 comes from elsewhere, and
  the victim is again a free remainder (believed 0xe00, real 0xe10).
  In the 4472 runs the donor-minus-O2 gap is a constant 0xe10 —
  request 2's decode buffers and O2 share the same free region, so a
  length-only sweep cannot produce an exact fit.

Structural lesson: `malloc` front-splits O2 from whatever free donor
it finds, so the NUL victim is that donor's remainder unless O2
exact-fits; and request 2's own decode allocations bite the groomed
donor before the ALTSVC call. **Both validator flavors prove any
FREE victim aborts inside the same request** — the completing regimes
are exactly victim==top (shrunk or flag-only). The rung-4 condition
remains: an in-use chunk must directly follow an exact-fit O2. Next
step (bytes planned): mtrace request 2's allocation sequence (sizes,
lifetimes, and the 0xb10/0xbf0 bites) to design the donor so the bite
lands first and O2 exact-fits what remains, abutting live memory.

### Rung-4 step 2 — mtrace donor-chain map; exact-fit groom lands; the in-call free closes the in-use lane (seventh wake, 2026-11-20 10:54Z)

`run-multi.sh` gained an `MT=1` mode (LD_PRELOAD the committed
`lab/preload/mtrace.so` into the gdb inferior; M/F lines interleave
with the walk markers — wake-4 mechanism, gdb+mtrace in one inferior).
Raw logs gitignored under `lab/node2shell/tmp/w6/`.

**Request-2 allocation timeline, measured** (LEN=2200/LEN2=2208 mtrace
run, `multi-run2.log`): request-1 teardown frees an
`M(authority_1+38)` chunk (2200→2238→chunk 0x8d0; the +38 scaling was
confirmed at authority 2184→2222→0x8c0) and allocates a
`M 0x117c` (2×2238) chunk that stays live through the abort.
Request 2 then, in order: hd-inflate bite `M(authority_2+57)`
(2208→2265→chunk 0x8f0) lands AT O1's old address, front-splitting the
consolidated O1+copy donor (bite+remainder 0x8f0+0x890 = donor 0x1180,
matching the wake-6 golden donor); nghttp2 origin-copy `M(origin_2+1)`
(2217) is **whole-served from the 0x8d0 8be chunk** (need 0x8c0,
0x10<MINSIZE); a second copy elsewhere; copy freed; then **O2's
`malloc(origin_2)` reuses the copy's freed chunk** — the O2 donor is
request-2's own nghttp2 origin copy, recycled from request-1's
teardown chunk, not the O1-region remainder. Donor 0x8d0 → split →
0x20 free-remainder victim → abort; donor 0x8c0 (LEN=2184) →
whole-served → the NUL lands in O2's own-chunk slack → **completed
2/2 with zero corruption** (negative result: whole-serving silently
kills the write; check O2's sizefield, not just its address).

**Exact-fit groom (LEN=2216, LEN2=2208, bare env)**: authority_1 2216
→ origin 2224 (≡0 mod 16, harmless) → donor 0x8c0+0x8e0 = 0x11a0 (the
measured +0x20-per-16 scaling), bite 0x8f0 → remainder **exactly
0x8b0 = O2's chunk size**. Observed in the fresh-0x8f0-bite regime:
`O2 == HOLE1-NEXT` (0x6e51630, sizefield 0x8b1, **no split, no
whole-serve**), NUL on the following chunk at 0x6e51ee0 → sizefield
**0xb00** — and the new REAL-NEXT-CAND scan pins the real size: the
real next chunk at V+0xbf0 holds sizefield 0xbf1, so the victim is the
**in-use golden 0xbf0 chunk: real 0xbf0 → believed 0xb00, shrink
exactly 0xf0**. The layout is bimodal per boot: when request-2's
hd-inflate bite is the grown 0xbf0 buffer instead of the fresh 0x8f0
one, the remainder is 0x550 and O2 goes elsewhere (free-remainder
victim → in-call abort). Batch results A/A, B/B, A/A (DELAY 300/4000
did not switch it); repeat runs until the walk prints
`O2 == HOLE1-NEXT`.

**Mechanism discovery — the same-call free closes the in-use lane.**
The exact-fit run's abort backtrace is NOT the in-call malloc
validator:

```
malloc_printerr: "double free or corruption (!prev)"
_int_free_merge_chunk (av=main_arena, p=0x6e51630, size=2224)
_int_free ← node::http2::Http2Session::AltSvc
```

node frees the origin buffer **inside the same C++ AltSvc call** that
wrote the one-past NUL. The NUL zeroes the victim sizefield's byte 0 —
which always holds PREV_INUSE — so `free(O2)`'s
`!prev_inuse(nextchunk)` check aborts for **any** non-top successor,
free or in-use, before any later allocation can reuse the corruption.
This precisely explains the wake-6/3.5 result that the only completing
regime is victim==top (the top merge is an else branch with no !prev
check). The "in-use victim with completing request" golden layout is
**structurally unreachable through session.altsvc's own buffer** —
upgraded from an inventory coincidence to a mechanism-backed closure.

**The remaining lane (design, bytes partially in hand):** make the
victim a **free** chunk at NUL time whose believed-shrunk extent the
in-call malloc **splits** — `set_head(victim, nb|PREV_INUSE)` restores
the cleared bit, `free(O2)` passes, and the request completes holding
an orphaned real tail ([V+believed, V+real]) behind an
attacker-groomed fake believed-next header. Gates: the victim must be
in unsorted/largebin at the in-call malloc, and its believed-next
sizefield (victim tail bytes = prior request content) must pass the
`invalid next size (unsorted)` sanity window — 'aaaa' content fails
(0x6161… ≥ system_mem); a prior request's authority bytes can place a
valid fake sizefield (e.g. 0x21) at exactly V+believed+8, making the
free-chunk split survivable and the tail overlap reachable. The
wake-6 free-victim aborts are this lane's current failure mode, not a
closure. `walk.py` now prints `VICTIM-BELIEVED-NEXT` and scans for the
real next chunk (REAL-NEXT-CAND) to measure victim real size and tail
content next.

### Rung-4 step 3 status — donor lane closed by the outbuf eater; fake
placement verified; slack junk is the remaining blocker (wake 9,
2026-11-20 12:14Z)

Wake 8's donor design (fake sizefield at the consolidated donor's alt
tail) is closed by a deterministic eater, identified with the committed
mtrace preload (`MT=1`): at request-1 response time the nghttp2 session
output buffer doubles `M(2252) → M(4504)` (nb 0x11a0 — the exact
consolidated-donor size) and eats the whole donor at every boot. The
attacker-content surface instead becomes the three freed ALTSVC "twins"
(node's frame copy `[origin+NUL][alt+NUL]`, nghttp2's submit copy
`[origin][alt]` without NULs, and the serialized old outbuf), one of
which serves request 2's origin buffer.

The fake-placement equation was verified byte-exact: at LEN=2212,
ALT=12, LEN2=1216 (O2 nb 0x4D0, victim believed 0x400), the walk read
`VICTIM-BELIEVED-NEXT sizefield=0x31bc0023` — the `'#'`(0x23)+NUL pair
landed exactly at victim+believed+8, as designed. The remaining blocker
is two stale bytes at fake+2..+3 (`31 bc`, deterministic across boots
at this chunk class): fake positions are ≡8 (mod 16) and string writes
can never cover the ≡0xA/0xB slack, so the fake's upper bytes are
chunk-history. Plan: sample other chunk classes / restrict O2 to the
frame-copy twin only; both are parameter sweeps of the same committed
harness (`walk.py` now also prints a zero/nonzero content profile of
the victim span). Wake-9 logs: `lab/node2shell/tmp/w6/multi-run*.log`
(gitignored lab artifacts).


### Rung-4 step 3 — own-NUL lane falsified; the `!prev` split gate
identified (wake 11, 2026-11-20 16:20Z)

The wake-10 "R1-origin-twin own-NUL" design was measured and **fails
structurally**, not by bad luck. Harness additions (committed): `OUT`
override in `run-multi.sh` (keeps one wake's logs out of another's), an
`ALT_HEX` env path in `node2shell-rung1-server.js` for arbitrary ALTSVC
bytes, and `FAKE-PAIR` diagnostics in `walk.py` that dump the
`o1+0xF+len1` qword at both submit hits.

- Run `LEN=2193 LEN2=1936 A1TAIL=Z` (4 boots, `w11/multi-run*.log`):
  HIT-2 O2 sizefield `0x7a1` matched the prediction exactly; O2 landed on
  O1's address in 2/4 boots — but in those boots O2-VICTIM's believed
  size was `0x900`, with believed-next `0x0` (abort `invalid next size
  (unsorted)`). In the one boot where the victim was small (believed
  `0x100`, `w11mt/` with mtrace env), O2 was elsewhere. Algebra: when O1
  consolidates with the adjacent free `0x890` chunk, the carve source
  F is `0x1140`, so `X + believed = F − lowbyte ≈ 0x1100` for **every**
  X — the required `0x8a0` is unreachable. Wall's lane closed.
- The R1-origin tail itself is a perfect fake at HIT 1
  (`FAKE-PAIR@HIT1 … qword=0x7a`, i.e. `[z][NUL][6 zeros]`), but at HIT 2
  the same address reads `0x6161616161616161`. The carrier's tail bytes
  are overwritten between requests; "its content survives free" is
  false for the bytes that matter (`w11fp/multi-run1.log`).
- Embedding the fake NUL inside the ALTSVC value is rejected by Node:
  `ALT_HEX=…7a00…` gives `TypeError [ERR_INVALID_CHAR]: Invalid
  character in alt` at `ServerHttp2Session.altsvc` (client ECONNRESET,
  `w11alt/`). That lane is closed by the runtime, not by layout.

**Corrected free(O2) gate.** The NUL clears V's PREV_INUSE bit as well
as its size magnitude, so `free(O2)` aborts with `double free or
corruption (!prev)` unless the in-call malloc **splits** V, which
restores the bit via `set_head(victim, nb|PREV_INUSE)`. Reproduced wake
9's byte-exact placement at `LEN=2212 ALT=12 LEN2=1216`
(`w11w9/multi-run1.log`): victim believed `0x400`, believed-next
sizefield `0xd0` — sane, so the unsorted scan passes — yet the request
still aborts at `free(O2)`: V (`0x400`) is smaller than the in-call
request `nb(o1+A)=0x8c0`, so it is never split. In the C1-carve
geometry this is general: `C1 ≈ request+0x20` and heap-backed O2 forces
`X ≥ 0x410`, hence `V = C1−X < request` always. All C1-carve fake lanes
are therefore unable to reach the split. A splittable V needs O2 carved
from a **larger consolidated region** (`F ≈ 0x1140`, `V ≈ 0x900 ≥
request`), where the remaining problem is placing a sane sizefield at
`V+believed+8` from request-1 buffer history. A 4-length groom-header
sweep (`w11groom/`) read garbage there (`0x3a9435f3`, `0x582c…`), with
no alignment; a 10-point `LEN` sweep (2113…2257, step 16, `LEN2=1936`,
`w11lensweep/`) likewise found only `0x6161…` (too large) or `0x0`
(too small) at believed-next — no natural sane fake in that regime.
All wakes' logs are gitignored lab artifacts under
`lab/node2shell/tmp/w11*/`.


**Second fake field, and debugger validation of the full gate chain.**
Patching only the believed-next sizefield to `0x5a` advanced the abort
from `invalid next size (unsorted)` to `malloc(): mismatching
next->prev_size (unsorted)` (`w11patch2/multi-run2.log`): glibc also
requires `prev_size(next) == believed`. With both fields written
(`prev_size=0x900`, `sizefield=0x5a`) the abort advanced once more to
`double free or corruption (!prev)` at `free(O2)`
(`w11patch3/multi-run1.log`) — exactly the split gate above. Finally,
with V's sizefield forced to `0x900` (≥ request, via the opt-in
`FAKE_VSIZE` diagnostic) *and* both fake fields written, glibc's malloc
validators were passed: `w11full/multi-run1.log` dies later with
`SIGSEGV in nghttp2_map_find` under `nghttp2_submit_altsvc`, and run 2
times out without a malloc abort. This confirms the three gates
(sane sizefield, matching prev_size, splittable V) but the injected
overlap breaks live nghttp2 state; these are **debugger interventions,
not attacker bytes**, so they are mechanism evidence only, not rung 4.
`walk.py` keeps these writes behind `FAKE_PATCH`/`FAKE_VSIZE` env vars
and prints them explicitly in the log.

### Rung-4 step 3 — exact glibc validator chain; the splittable O2==O1 geometry (wake 12, 2026-11-20 16:52Z)

Host glibc identified as 2.39 (`ldd --version`: `Ubuntu GLIBC
2.39-0ubuntu8.12`). The exact unsorted-scan validator chain was read
from glibc 2.39's `malloc/malloc.c` (lines 4078-4088; fetched copy
`lab/node2shell/tmp/glibc-2.39-malloc.c`, gitignored):

1. `size <= 2*SIZE_SZ || size > system_mem` → `invalid size (unsorted)`;
2. `chunksize_nomask(next) <= 2*SIZE_SZ || > system_mem` → `invalid next size (unsorted)`;
3. `prev_size(next) != size` → `mismatching next->prev_size (unsorted)`;
4. `bck->fd != victim || victim->fd != unsorted_sentinel` → `unsorted double linked list corrupted`;
5. **`prev_inuse(next)` set → `invalid next->prev_inuse (unsorted)`**.

Check 5 is the inverse of an earlier assumption: a free victim's
believed-next must have PREV_INUSE **clear**. Empirical confirmation:
in the O2==O1 geometry, patching the fake sizefield to `0x21` (odd)
advanced the abort to `invalid next->prev_inuse (unsorted)`
(`w12p/multi-run7.log`, believed-next 0x6e51090 patched to
`prev_size=0x900, sizefield=0x21`), while wake-11's even `0x5a`/`0xd0`
fakes passed it. The attacker's fake sizefield must therefore be an
even value in `[0x20, system_mem]`; the three earlier "gates" become
five conditions, all of which can be met by a real chunk header at the
believed-next address.

The O2==O1 layout (request 2's origin reuses request 1's origin
address, ~1/4 of boots at LEN=2193/LEN2=1936) is the splittable case:
measured `w12n/multi-run1.log` gives O1=O2 chunk 0x6e4f520 (sizefield
0x7a1), victim V=0x6e4fcc0 free in the unsorted bin with believed size
0x900 ≥ the in-call request's nb (~0x7b0), so an in-call malloc split
would restore V's PREV_INUSE and let `free(O2)` pass. The fake window
`V+0x900 = 0x6e505c0` currently holds request-1's copied-origin 'a'
filler; a marker scan locates the copy twin's `'z'+NUL+'h2x:80'` at
0x6e50688, i.e. 0xc8 past the fake window. Instrumentation added to
`walk.py` (O2==O1 victim/marker/header diagnostics and a debugger-only
FAKE_PATCH path there) preserves this for the next wake. Whether a
length-only groom can put a real chunk header at the fake window —
making `prev_size(next)==believed` and an even, sane sizefield arise
from genuine heap metadata rather than injected bytes — remains
UNKNOWN.

**Full gate chain passed in the splittable geometry (debugger patch, not
attacker bytes).** With the O2==O1 / V=0x900 layout and `FAKE_PATCH=0x20`
(even fake sizefield, matching prev_size), 8 boots (`w12e/`): the 5
O2==O1 runs all had V free in unsorted with believed 0x900 ≥ request;
4 of them (runs 4, 5, 6, 8) passed every glibc validator and the process
stayed alive — the client printed `ALTSVC-1`, `ALTSVC-2`, `DONE hits=2`.
One (run 1) still aborted `invalid next size (unsorted)` despite all
five visible V checks passing (unresolved variance, possibly a later
malloc on a different unsorted chunk); the 3 non-O2==O1 boots aborted
as before (`invalid next size` / `!prev`). This upgrades the wake-11
mechanism claim: in the O2==O1 geometry the attacker needs only to make
the two fake fields at `V+believed` read as a real free-chunk boundary,
and the unsorted scan splits V, `free(O2)` succeeds, and the request
completes holding the overlap. Whether attacker-chosen lengths can
create that boundary without debugger writes is under test.

**Natural fake-field sweep — negative.** With the O2==O1-friendly
lengths LEN=2193/LEN2=1936 and ALT lengths swept 10, 18, 26, 34, 42,
50, 58, 66, 74, 82, 90, 98, 106 (2 boots each, `w12as*/`), the two fake
qwords at `V+believed` only ever read the two attacker fillers:
`0x6161616161616161` (origin filler, believed 0x900) for ALT ≤ 42, and
`0x3838383838383838` (ALT filler, believed 0xa00) for ALT ≥ 74. Neither
is a sane even sizefield with a matching prev_size; the transition
between ALT 50 and 66 moves V's believed size from 0x900 to 0xa00 as
the donor grows, but never exposes a real chunk header at the fake
window. Attempts to force that boundary by changing L1/ALT/LEN2
(`w12nat/`: LEN=1916/ALT=96 → V believed only 0x100, no copy-twin
marker inside V; `w12nat2/`: LEN2=2224/ALT=74 → 0/14 O2==O1 boots)
also failed. The attacker-controlled bytes are present at the exact
offset, but both HTTP/2 strings reject embedded NULs, so the required
`[00][believed>>8][6 zero bytes]` prev_size cannot be written as string
content. This is a preserved negative, not a retried-into-existence
claim.

### Rung-4 step 3 — LEN2 sweep and NUL-channel closure (wake 13, 2026-11-20 17:30Z)

**LEN2 sweep — negative.** Wake 12 swept the ALTSVC value length; this
wake swept the other length axis with the O2==O1-friendly first
request fixed at `LEN=2193` (origin 2201). `LEN2 ∈ {1872, 1904, 1920,
1936, 1952, 1968, 1984, 2000, 2032, 2064}`, 5 fresh gdb boots each,
logs `lab/node2shell/tmp/w13s*/` (gitignored). Every boot that reached
the O2==O1 geometry (`same=True`: 1/5, 1/5, 2/5, 3/5, 3/5, 1/5, 2/5,
2/5, 2/5, 0/5 respectively) showed the same two fake-window qwords:
`prev_size=0x6161616161616161 sizefield=0x6161616161616161`
(origin `'a'` filler) at `V+believed`, and a believed size of `0x900`
for all `LEN2 ≥ 1904`. The single exception, `LEN2=1872`, moved the
fake window onto the origin-tail boundary:
`prev_size=0x6161616161616161`,
`sizefield=0x30383a7832680061` (bytes `61 00 68 32 78 3a 38 30`,
i.e. last origin byte, NUL, then ALT text). Its low byte `0x61` is odd
and the six upper bytes are ASCII, so `chunksize_nomask ≫ system_mem`:
`malloc(): invalid next size (unsorted)` still fires. `LEN2=2064`
produced no O2==O1 boots. The in-call malloc request grows with LEN2
(`bytes = LEN2+36`: 1940 at 1904, 2036 at 2000) but the victim stays
`0x900`, so no exact-fit escape appeared either. No natural chunk
header lands at the fake window on this axis.

**Both attacker string channels cannot carry NUL — re-tested
directly, not taken from the prior wall.** With the committed server
(`ALT_HEX` feeds a latin1 ALTSVC value), `ALT_HEX=61006832`
(`a NUL h 2`) makes `session.altsvc()` throw
`TypeError [ERR_INVALID_CHAR]: Invalid character in alt` before the
request completes (client `ECONNRESET`). A client request whose
`:authority` contains `\0` is rejected by nghttp2 with
`NGHTTP2_PROTOCOL_ERROR` before any ALTSVC call. So neither the ALT
value nor the origin can place the required
`[00][believed>>8][00×6]` fake `prev_size` qword; the only NUL at that
offset is the library's own terminator, at the origin/data boundary.

**Measured overlap window.** In the `LEN2=1872` boot
(`w13s1872/multi-run5.log`), V is at `0x6e4f100` with believed size
`0xa00`; the real next-chunk boundary is at `0x6e4f100+0xa10 =
0x6e4fb10`, whose header reads `prev_size=0xa10 sizefield=0xbf0`
(even, sane). The fake boundary at `V+0xa00 = 0x6e4fb00` lies `0x10`
inside V's real extent and holds `'a'*8` plus the origin-tail marker.
This is the believed-extent-inside-real-extent overlap, byte-measured,
but it cannot be consumed while the fake header is unforgeable with
attacker bytes.

Ladder read unchanged: rung 3/3.5 mechanism plus a debugger-only
demonstration that all five glibc gates pass with a synthetic header;
rung 4 remains open on a NUL-capable content channel or a geometry
where `set_foot` writes the believed size at the fake window (victim
freed *after* corruption, not split before it).

### Rung-4 step 3 — freed-after-corruption lane measured; tcache and
### `!prev` closure (wake 14, 2026-11-20 17:51Z)

Wake 13 proposed changing the *timing* so the corrupted chunk is freed
after the NUL, letting glibc's own `set_foot` write the fake
`prev_size`. The only second heap buffer in the vulnerable function is
`MaybeStackBuffer<uint8_t> value(value_len)`, declared immediately
after `origin` and destroyed before it
(`node_http2_v24.22.2.cc:3324-3334`). With a 1200-byte printable ALT
`value` is heap-allocated; harness extension `VALUE-WALK` dumps the
`r9` argument at the `nghttp2_submit_altsvc` breakpoint
(`walk.py`, `FAKE_SIZEONLY` is a debugger-only opt-in). Logs:
`lab/node2shell/tmp/w14val2/`, `w14patch2/`, `w14ctrl/` (gitignored).

**The lane is real.** In `w14patch2/multi-run1.log` request 2 has
`origin chunk=0x6e50890 size=0x7a0`, `value chunk=0x6e51030`:
`adjacency delta=0x0` (value starts exactly where origin ends) and
`origin-NUL@0x6e51038 value+8=0x6e51038 match=True`. `value`'s
sizefield reads `0x400` (real `0x4c0` for a 1200-byte value), i.e. the
library's own terminator zeroed its low byte. `value` is still in use
at the submit breakpoint and is destroyed after it — corruption
precedes the free, exactly the desired timing.

**Two gates move, one does not.** `FAKE_SIZEONLY=0x20` wrote a sane
even sizefield at the fake window `value+0x400` (debugger, not
attacker bytes). The abort was unchanged:
`double free or corruption (!prev)` from
`_int_free_merge_chunk (p=0x6e50890, size=1952)` at glibc 2.39
`malloc.c:4679`, in `free(origin)` — i.e. `free(value)` itself had
already succeeded. Reason: the believed size `0x400` is in tcache's
size range, whose fast path does not consult the next-chunk header at
all, so neither the forged `prev_size` nor the fake sizefield was ever
tested. The fatal check is `!prev_inuse(nextchunk)`: `nextchunk` is
`value`, whose sizefield low byte the NUL zeroed, so its PREV_INUSE
bit is 0. That bit is *invariant* under this primitive — a NUL can
only clear it — so the chunk immediately before the corrupted one can
never be freed afterwards. Here that chunk is `origin`, freed by the
declaration-order destructor immediately after `value`; no allocation
or split intervenes to restore the bit (contrast wake 12, where the
in-call malloc split the victim before `free(O2)`).

**Control and reproducibility.** With the same long ALT but no patch,
`w14ctrl` had 1/3 adjacent boots (`delta=0x0`) and `w14final` had 3/3
(`delta=0x0`, `origin-NUL match=True`, believed `0x400`, fake window
`'A'*8` in all three); every adjacent boot aborted at the same
`_int_free_merge_chunk` `!prev` check, patched or not. In the two
non-adjacent `w14ctrl` boots (`delta=-0x4a60`, `-0x48e0`), origin's NUL
hit a non-adjacent free chunk and the abort moved to `unlink_chunk`
(`malloc.c:1611`) — a separate negative, not a lane.

**Structural read.** The two size regimes are now both closed under
ASCII-only attacker strings: (a) a corrupted chunk at or below
tcache's maximum never runs the next-chunk validator chain, but the
NUL-cleared PREV_INUSE bit makes the preceding chunk's later free
abort; (b) above tcache the chain runs, and wake 13 measured that the
fake window needs a NUL-bearing `prev_size` and a sane even
sizefield — neither reachable from the origin or ALT strings. No
length-only sweep was repeated. Ladder unchanged: rung 3/3.5
mechanism, rung 4 not demonstrated.

Wake-14 value-buffer walk (long ALT; ~2 s per boot):

```
ALT_HEX=$(python3 -c "print('41'*1200)") OUT=lab/node2shell/tmp/w14 \
  LEN=2193 LEN2=1936 VALUE_LEN=1200 \
  sh lab/repro/node2shell-shrinkwalk/run-multi.sh <port> 3
# VALUE-WALK 2: adjacency delta=0x0 and origin-NUL match=True identify
# the boot where origin's NUL corrupts the adjacent value chunk;
# FAKE_SIZEONLY=0x20 adds a debugger-only sane sizefield for contrast.
```

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

Debugger walk of the victim chunk (rung 3/3.5; gdb 15.1, ASLR off,
~1 s per aborting run, ~75 s per serving run):

```
sh lab/repro/node2shell-shrinkwalk/run.sh <port>          # LEN=2208 default: origin 2216
LEN=1040 sh lab/repro/node2shell-shrinkwalk/run.sh <port> # origin 1048
# abort regime → VICTIM free remainder + "invalid next size (unsorted)" bt
# top regime   → TOP-VICTIM believed/real size + client: ALTSVC origin_len=…
```

Two-request hole inventory (rung-4 step 1; ~10 s per aborting run,
~40 s per run where request 2 completes):

```
sh lab/repro/node2shell-shrinkwalk/run-multi.sh <port> 4
LEN=3624 LEN2=4464 sh lab/repro/node2shell-shrinkwalk/run-multi.sh <port> 8
LEN=2216 LEN2=2208 sh lab/repro/node2shell-shrinkwalk/run-multi.sh <port> 4
# exact-fit regime: O2 == HOLE1-NEXT (sizefield 0x8b1, no split) and the
# abort is "double free or corruption (!prev)" in free(O2) — see step 2;
# bite-0xbf0 regime variant: O2 elsewhere, free-remainder victim instead
MT=1 LEN=2200 LEN2=2208 sh lab/repro/node2shell-shrinkwalk/run-multi.sh <port> 1
# mtrace timeline: M/F lines interleaved with the walk markers in the log
# (donor chain: 8be chunk → nghttp2 copy → O2; sizes are HEX)
# per run: HIT 1/HIT 2 walks, NUL-CLASS line (only ≡8 mod 16 corrupts),
# O2-VICTIM classification (FREE(unsorted) → validator abort; top → completes)
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
