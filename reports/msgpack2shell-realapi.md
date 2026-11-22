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

## Consumer reach — still UNKNOWN, with one negative result

In the pinned `c-7.0.2` tree the only call site of
`msgpack_vrefbuffer_migrate()` outside its own definition and public header is
`test/msgpack_c.cpp:1570` (a unit test asserting a `-1` return). No production
in-tree caller exists in this release. A bounded web query for downstream
callers returned advisories, API documentation and a vendored copy of the
source, but no identified wire-facing caller. Consumer and wire reach remain
UNKNOWN; the local/high-complexity CVSS vector in the advisory is unchanged.

## Honest ceiling

Reached: rung 3 (ASan-confirmed corruption in verbatim pinned code, frontier)
and rung 4 through the **real public API** of a built pinned library, with
differential fixed/safe controls. Not reached: no application consumer, no
serialized or request input, no socket, no plant-started loopback instance, no
dereference of a copied `iov_base`, no marker execution, no command, no rung 5.

Next: look for a downstream caller that reaches unequal-size `migrate()` from
request data; only then consider a plant-started loopback replay. A chosen
`iov_base` landing on a pointer-bearing field of an adjacent object remains
unmeasured. Mind-changers: a fixed pin faulting on a natural layout, a caller
that reaches unequal-size migrate with attacker-sized buffers, or chosen bytes
that turn out incidental.
