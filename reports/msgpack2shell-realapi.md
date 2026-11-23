# msgpack2shell W1: real public API reaches the migrate overflow on a natural heap layout

Date 2026-11-22. Target: GHSA-8pq6-mw7r-9f5g / CVE-2026-130065, upstream
`msgpack/msgpack-c#1197`. This report advances frontier's direct-call evidence
(`reports/frontier-msgpack2shell.md`) to a real pinned C-library build driven
only through the public API. Evidence: `lab/msgpack2shell/`, replay with
`bash lab/msgpack2shell/run.sh`.

## Question and result

Question: does `msgpack_vrefbuffer_migrate()`'s cross-object comparison
(`to->tail + nused < vbuf->end`, destination-derived pointer versus **source**
array end) actually evaluate false on a natural two-allocation heap layout,
without a harness forcing `src->end` — and is the path reachable from a caller?

Result: **yes on a natural layout in this lab**. The upstream two-migrate
variant faults through `init`/`append_ref`/`migrate` alone on the vulnerable
release pin under both gcc 13.3.0 and clang 18.1.3 with ASan, and aborts under
plain glibc. The fixed commit and the equal-capacity safe control are clean.
This is a rung-4 measurement through the real public API in a local library
build. It is **not** rung 5: no consumer, no request/wire input, no live
process, no pointer dereference, no marker, no command.

## Reproduction

Sequence (public API only; `api_repro.c` argv `4`):

1. `msgpack_vrefbuffer_init(&A,0,0)`, `init(&B,0,0)` — on this host each
   allocates 4 iovec slots (`72/sizeof(struct iovec)`).
2. five `append_ref(&A,...)` — A grows to cap 8, used 5.
3. `migrate(&A,&B)` — B grows to cap 8, used 5; A resets to used 0.
4. four `append_ref(&A,...)` — A used 4.
5. `migrate(&A,&B)` — `to->tail+nused = B.array+9`, `vbuf->end = A.array+8`.
   Natural allocation order puts B above A, so the comparison is false; growth
   is skipped; `memcpy` copies 4 iovecs (64 bytes) from `B.array+5`, one slot
   past B's 8-slot (128-byte) allocation.

Instrumentation (reading public fields only) printed `cmp=0` for the comparison
on every variant, vulnerable and fixed, on both compilers.

## Measured outcomes

`bash lab/msgpack2shell/run.sh`: **74 PASS / 0 FAIL**, `rc=0`, summary hash
`b8c96187de5cbf66bc53cc1b350d977eab95e5cda5351875c992136880bca022`.

| pin | mode | two-migrate (4 refs) | safe control (2 refs) | canary PoC |
|---|---|---|---|---|
| `c-7.0.2` | ASan | `heap-buffer-overflow`, `WRITE of size 64`, `0 bytes after 128-byte region`, frame `msgpack_vrefbuffer_migrate vrefbuffer.c:222`, allocation from `realloc` in `vrefbuffer.c:210` (prior migrate). `rc=134`. | clean, B `cap=8 used=7` | — |
| `c-7.0.2` | plain | `free(): invalid size`, `rc=134` | clean | canary `CORRUPTED`, first byte 0, `rc=134` |
| `1c47ce0` (fixed) | ASan | clean, B grows `cap=16 used=9` | clean | — |
| `1c47ce0` (fixed) | plain | clean, B grows `cap=16 used=9` | clean | canary `intact`, `rc=0` |

The single-migrate plain-glibc canary PoC from the upstream issue also
reproduces here: `vbuf nused=20`, `to usable=136`, `bytes_to_copy=320`,
canary `CORRUPTED`, `free(): invalid size`. The fixed pin leaves it intact.

## Consumer reach — measured NEGATIVE in indexed public source (2026-11-22)

Independent searches answer the consumer question negatively:

1. **In-tree:** in pinned `c-7.0.2`, the only `msgpack_vrefbuffer_migrate()`
   call site outside its definition and public header is `test/msgpack_c.cpp:1570`,
   a unit test asserting a `-1` return. No production caller in the release.
2. **Downstream:** GitHub code search (authenticated `gh api search/code`) for
   `msgpack_vrefbuffer_migrate` returned 658 indexed files. Paginating all 700
   collected matches and filtering out the definition files (`vrefbuffer.c/.h`)
   left 113 paths; every source-code path among them is one of: the upstream
   unit test `test/msgpack_c.cpp` (in vendored msgpack-c copies); an OLD
   standalone C definition of the same function (`vrefbuffer.cpp/.cc` in
   HighwayFlocking, moon9, cchelp, aerys/minko, marvinguo/liangshi) — the
   definition, not a caller; or advisory/OSV/NVD databases, exported-symbol
   lists, dSYM dumps and notes. The same search for `msgpack_vrefbuffer_init`
   (592 indexed, 666 collected) has the identical shape: no production user of
   the API at all.
3. The vendored copy surfaced in W1, `TEN-framework/ten-framework`, has zero
   vrefbuffer references outside its `third_party/msgpack/` tree, in both a
   sparse and a full checkout.
4. The only `->migrate(&` + msgpack hit, `frsyuki/ccf src/ccf/session.h:186`, is
   `core::xfer::migrate`, an unrelated transfer-object method. The C++
   `msgpack::vrefbuffer` wrapper route is gone in the vulnerable pin:
   `include/msgpack/vrefbuffer.hpp` returns HTTP 404 on tag `c-7.0.2`.
5. Issue #1197's "Impact" section names no application. Its claim that "any
   application calling `msgpack_vrefbuffer_migrate()` ... with imbalanced
   buffer sizes is affected" is generic conditional prose, not a demonstrated
   caller or a request/wire path.
6. W134 independent cross-check (2026-11-23). Sourcegraph public code search
   for `msgpack_vrefbuffer_migrate` returned 53 exhaustive matches in 29 repos
   (default index) and 44 with `archived:yes fork:yes`. Every match is a
   vendored `vrefbuffer.c` definition, a `vrefbuffer.h` declaration, the
   upstream unit test, or a CVE/advisory database. That includes the official
   `msgpack/msgpack-node` and `msgpack/msgpack-objectivec` bindings and
   request-serving vendors (fluent-bit, griddb, OpenNJet, ytsaurus, Firefox /
   gecko-dev); a scoped query on those two bindings found only the definition
   and declaration. Excluding paths containing `vrefbuffer` leaves only
   advisory JSON/YAML. grep.app returned HTTP 429 and Debian Code Search's
   fetched page showed no results, so neither contributed evidence. Upstream
   tags rechecked the same day: newest C tag is still `c-7.0.2`; issue #1197 has
   two comments, neither naming a consumer or a fixed release.

Limit: both GitHub and Sourcegraph code search index public source only. An
unindexed private or out-of-tree caller remains UNKNOWN, not disproved; wire
reach stays UNKNOWN.

Also checked: no fixed C release exists. The newest C tag is `c-7.0.2` and the
fix commit `1c47ce0` (2026-10-29) is master-only, so the advisory's missing
patched-version field is correct.

Disposition: with no identified consumer to receive request data, there is no
loopback replay to run and no exploit mechanics to attempt. The measurement
stops at rung 4 — a wire path would have to be manufactured. Reopen only on
evidence of a real caller of the C vrefbuffer API in a request-serving process;
keep the fixed pin and the equal-capacity 2-ref control as differential
controls in any such replay.

## Honest ceiling

Reached: rung 3 (ASan-confirmed corruption in verbatim pinned code, frontier)
and rung 4 through the **real public API** of a built pinned library, with
differential fixed/safe controls and a measured negative on consumer reach.
Not reached: no application consumer, no serialized or request input, no
socket, no plant-started loopback instance, no dereference of a copied
`iov_base`, no marker execution, no command, no rung 5.

Disposition: stopped at rung 4. Reopen only if a real caller of the C
vrefbuffer API in a request-serving process is found (an unindexed private
fork remains UNKNOWN). Mind-changers: a fixed C release tag, such a caller
reaching unequal-size migrate with attacker-sized buffers, the fixed pin
faulting on a natural layout, or chosen bytes that turn out incidental. A
successful sample alone never resolves a cause.
