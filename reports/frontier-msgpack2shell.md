# Frontier brief: msgpack-c `msgpack_vrefbuffer_migrate()` — GHSA-8pq6-mw7r-9f5g / CVE-2026-130065 (msgpack2shell)

Status W125 (2026-11-22): screened in and staged at rung 3 (ASan-confirmed heap
out-of-bounds write in a verbatim pinned function) plus a scoped rung 4 (chosen
`iov_base` pointer and `iov_len` bytes at chosen offsets past the destination
array, direct-call/stub scope). Duplicate check before provisioning: no prior
`reports/frontier-*msgpack*`, no msgpack window/charter/mind on the tape, and
msgpack is absent from the do-not-duplicate list in `walls/frontier.md`.

**Revision of a parked disposition.** `reports/frontier-pnet2shell.md` §6 parked
this candidate unmeasured ("interesting pointer-shaped data, but local library
API only, no fixed release tag, consumer/wire reach a claim"). This wake
re-opened it with a measurement: the exact one-line fix, three verbatim pins and
a deterministic ASan trigger now exist locally. The three parked caveats remain
true and are recorded below rather than silently resolved. Operator owns final
admission; wake units and full-flag sync stay with the person.

## 1. Verified ground truth

- Claim: GHSA-8pq6-mw7r-9f5g, "msgpack-c through 7.0.2 contains a heap buffer
  overflow", CVE-2026-130065, CNA VulnCheck, published to GHSA 2026-11-17
  (NVD 2026-11-16). Moderate, CVSS v4 5.8,
  `CVSS:4.0/AV:L/AC:H/AT:P/PR:N/UI:P/VC:N/VI:H/VA:L/SC:N/SI:N/SA:N`,
  CWE-787. **Attack vector is local, complexity high, user interaction passive**;
  no remote or unauthenticated claim is made by the advisory.
- Claim source read (read-only provisioning, no external probe):
  `https://github.com/advisories/GHSA-8pq6-mw7r-9f5g`. Supporting sources:
  NVD/CVE record, OSV `CVE-2026-130065`, upstream issue
  `https://github.com/msgpack/msgpack-c/issues/1197` (opened 2026-10-28,
  closed), fix commit `1c47ce020a019a3d4246e6394176779ecdf9d502`
  (2026-10-29, "check destination capacity in msgpack_vrefbuffer_migrate").
- Affected / patched fields: advisory says "through 7.0.2" and leaves both
  affected and patched versions "Unknown"; **no fixed release tag is visible**.
  The fix is a real commit on `c_master` with parent
  `8a34070b41827a179e7c4a102f34d8c0a2bd5a77`. The shipped release pin `c-7.0.2`
  and the fix parent have byte-identical `migrate()` bodies (they differ only in
  an unrelated `append_ref` wrap guard), so both are used as vulnerable pins.
- Primitive claimed: `msgpack_vrefbuffer_migrate()` decides whether to grow the
  destination iovec array by comparing a destination-derived pointer against
  the **source** array's end pointer. With unequal buffer sizes the realloc is
  skipped and `memcpy()` writes iovec entries (pointer + length pairs) past the
  destination array, corrupting adjacent heap memory or crashing. The upstream
  issue records a plain-glibc canary PoC (20 incoming vs 8 real slots, 192-byte
  overflow) and an AFL-minimized two-migrate ASan variant; neither upstream
  trigger was replayed here — they remain claims.

## 2. Source-bound mechanism and fix

Verbatim vulnerable pin `8a34070b` (and identically `c-7.0.2`),
`src/vrefbuffer.c` inside `msgpack_vrefbuffer_migrate()`:

```c
const size_t nused = (size_t)(vbuf->tail - vbuf->array);
if(to->tail + nused < vbuf->end) {
    /* grow to->array with realloc */
}
memcpy(to->tail, vbuf->array, sizeof(msgpack_iovec)*nused);
```

`to->tail` belongs to the destination allocation, `vbuf->end` to an unrelated
source allocation; comparing them is undefined behavior (C11 6.5.8p5) and its
truth value follows heap layout, not free room in `to`. When it is false the
growth block is skipped and the `memcpy` writes `nused` 16-byte iovecs from
`to->tail` regardless of `to->end`.

The one-line fix compares a count of free slots in the object actually written:

```c
-        if(to->tail + nused < vbuf->end) {
+        if(nused > (size_t)(to->end - to->tail)) {
```

`8a34070b` -> `1c47ce0` changes exactly this one line. The fix commit also adds
39 lines of regression test (`test/buffer_c.cpp`,
`vrefbuffer_c_migrate_grows_destination`) that migrates between two buffers and
asserts the destination grew to 40 used iovecs with `tail <= end`.

## 3. Measured evidence (this lab)

Everything lives in `lab/frontier/msgpack2shell/`. `harness/gen_fn.py` extracts
the function byte-for-byte from each pin into three `.inc` files verified by
`harness/verify_verbatim.py`. `harness/harness.c` supplies only the pinned
struct layout, a scripted 20-iovec source (`iov_base=0x4141414141414141`,
`iov_len=0x5a5a5a5a5a5a5a5a`), an 8-slot destination, and a plain-mode arena
that makes the bytes past the real 128-byte allocation readable. `src->end` is
set to `dst->array` to force the buggy comparison false — the advisory's
"destination above source" layout; the pointer is compared, never read through.

`bash lab/frontier/msgpack2shell/harness/run.sh` — **177 PASS / 0 FAIL**, `rc=0`,
two rounds with byte-identical normalized hash
`7edebe0e03a6244e0c659c99763fbf39e3420cd71b0b55e2961e51cb16c9b794`
(gcc 13.3.0 + clang 18.1.3). Full logs and pin hashes: `harness/evidence/`,
`harness/PROVENANCE.md`.

- Vulnerable pins (`c-7.0.2`, `8a34070b`), both compilers: ASan
  `heap-buffer-overflow`, `WRITE of size 320`, `0 bytes after 128-byte region`,
  `#1 ... in msgpack_vrefbuffer_migrate fns-8a34070b.inc:46` above `memcpy`.
- Vulnerable pins, plain mode: 20 iovecs copied at offsets 0..320; 12 chosen
  entries at offsets 128..320, `OOB_FIRST_BASE=4141414141414141`,
  `OOB_FIRST_LEN=5a5a5a5a5a5a5a5a`, `OOB_PAST_CAP=12`, tail sentinel intact.
  This is chosen-pointer bytes at a chosen offset, not a pattern-derived write.
- Fixed pin (`1c47ce0`), both compilers/modes: `DST_CAP_AFTER=32`,
  `DST_USED_AFTER=20`, `OOB_PAST_CAP=-12`, no ASan report. The same 320-byte
  copy stays inside the grown destination.
- Safe control (4 incoming iovecs, 8 real slots): clean on all three pins and
  both compilers, with `INBOUND_CHOSEN=1`.

## 4. Honest ceiling / rung-4 feasibility

Reached: rung 3 (ASan-confirmed heap corruption in verbatim pinned code) and a
scoped rung 4 (chosen iovec pointer+length bytes at chosen offsets, direct-call
scope). **Not** reached: no msgpack build, no public `vrefbuffer_init` /
`append_ref` / `clear` API sequence, no crafted serialized input, no consumer,
no wire, no naturally observed heap layout (the cross-object comparison is
forced by the harness), no dereference of the chosen pointer, no marker
execution, no command, no rung 5. The advisory's local attack vector and
"potential further impact" are unchanged claims. Consumer/wire reach remains
UNKNOWN — the parked caveat is preserved.

Cheapest next experiments, in order: (1) compile the pinned `c-7.0.2` C library
and drive the upstream issue's two-migrate ASan variant through the real public
API, without forcing `src->end`, to see whether this allocator reproduces it;
(2) find an in-tree or downstream caller of `msgpack_vrefbuffer_migrate()` and
determine whether unequal-size migrate is reachable from request data;
(3) only then consider whether a chosen `iov_base` lands on a pointer-bearing
field of an adjacent object. Rung 5 stays additive and per-build.

## 5. Ranking and disposition

Tractability: high — one self-contained function, a one-line fix with exact
commit pins, deterministic differential evidence, and a rare pointer-shaped
OOB primitive. Impact ceiling is honest and narrow: local API, advisory claims
integrity/availability only, no established consumer. Ranked above the other
fresh 2026 candidates this wake because the fix hunk and trigger are exact and
the chosen bytes are real pointer/length pairs; rsync (fixed NULL bytes) and
Kamailio/libwebsockets (already owned) were not selected. Staged by frontier at
2026-11-22 with this brief, a charter, a seed wall and a live two-pane window;
the operator owns final admission. Frontier owns no further work on this lane
after staging.

Mind-changers: the fixed pin also faults under a natural layout, the chosen
bytes turn out incidental, or no real caller can reach an unequal-size migrate.
