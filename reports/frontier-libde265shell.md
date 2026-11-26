# Frontier brief — libde265shell (CVE-2026-33165 / GHSA-653q-9f73-8hvg)

Status: **staged 2026-11-26 by `frontier`; rung 3 confirmed locally on pinned
upstream sources with the advisory's public-API PoC; rung 4 PARTIAL (lab
WRITE-2, no chosen bytes/pointer). No wire path, command execution or r5.**
Every decode was local; only public advisory/source pages and tarballs were
fetched.

## Verified ground truth

- Advisory: https://github.com/strukturag/libde265/security/advisories/GHSA-653q-9f73-8hvg
  (maintainer report, published 2026-03-17, Moderate, CWE-787). Affected
  `<= 1.0.16`, patched `>= 1.0.17`. Claim quoted: "A crafted HEVC bitstream
  causes an out-of-bounds heap write confirmed by AddressSanitizer"; root
  cause "a stale `ctb_info.log2unitSize` after an SPS change where
  `PicWidthInCtbsY` and `PicHeightInCtbsY` stay constant but `Log2CtbSizeY`
  changes, causing `set_SliceHeaderIndex` to index past the allocated image
  metadata array and write 2 bytes past the end of a heap allocation."
- CVE cross-check: https://www.cve.org/CVERecord?id=CVE-2026-33165
- Tags verified with `git ls-remote`: v1.0.16
  `7ba65889d3d6d8a0d99b5360b028243ba843be3a`, v1.0.17
  `f3d916c8e63e510bda1f9cf5e8710259c22afece`.
- Fix commit fetched as raw patch:
  `c7891e412106130b83f8e8ea8b7f907e9449b658`
  https://github.com/strukturag/libde265/commit/c7891e412106130b83f8e8ea8b7f907e9449b658
  It adds `|| ctb_info.log2unitSize != sps->Log2CtbSizeY` to the CTB-info
  reallocation guard in `libde265/image.cc` and narrows
  `MetaDataArray::log2unitSize` to `uint8_t`. Confirmed against pinned source:
  v1.0.16 `image.cc:455-456` lacks the check; v1.0.17 `image.cc:417-419` has it.
- Pinned source, tarball and PoC SHA-256s are in
  `lab/frontier/libde265shell/PROVENANCE.md`. The advisory's POC.zip contains
  a 254-byte minimized `reproducer.bin` and a dependency-free `poc.c` that
  drives `de265_new_decoder` → `de265_push_data` → `de265_decode` →
  `de265_get_next_picture`, all public APIs.

## Source-bound mechanism

`de265_image::alloc_image()` reallocates `ctb_info` only when its width or
height changes (v1.0.16 `image.cc:455`). A second SPS in the same stream keeps
`PicWidthInCtbsY`/`PicHeightInCtbsY` but changes `Log2CtbSizeY`; the old
allocation's `log2unitSize` stays stale, so `MetaDataArray<CTB_info>::get()`
maps a CTB coordinate with the new unit scale past the old array. The decoder
then calls `set_SliceHeaderIndex()` (v1.0.16 `image.h:741`) from
`read_coding_tree_unit()` (`slice.cc:2866`), writing a 16-bit slice-header
index two bytes beyond the 2496-byte `ctb_info` allocation. The fix forces
reallocation when the log2 CTB size changes.

## Local reproduction (rungs 1–3)

`lab/frontier/libde265shell/run-all.sh` verifies all SHA-256 pins, builds both
tags with CMake (`BUILD_SHARED_LIBS=OFF`, `ENABLE_DECODER=OFF`, `ENABLE_SDL=OFF`)
under clang ASan, gcc ASan and gcc plain, links the unmodified advisory
`poc.c`, and runs both the 254-byte bitstream and a 254-byte zero-byte benign
control. Result on 2026-11-26: `RESULT PASS=12 FAIL=0`.

Vulnerable v1.0.16, GCC and Clang ASan, `evidence/1.0.16-{gcc,clang}-asan-reproducer.bin.out`:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 2 at 0x51e000000a42 thread T0
  #0 de265_image::set_SliceHeaderIndex(...) libde265/image.h:741:40
  #1 read_coding_tree_unit(thread_context*) libde265/slice.cc:2866:8
  ...
0x...a42 is located 2 bytes after 2496-byte region [0x...080,0x...a40)
allocated by MetaDataArray<CTB_info>::alloc(...) image.h:94 via
de265_image::alloc_image(...) image.cc:463
SUMMARY: AddressSanitizer: heap-buffer-overflow ... image.h:741 ...
```

The plain v1.0.16 build exits 0 silently, matching the advisory's "release
builds write silently" observation (no fault asserted). Fixed v1.0.17 exits
0 with no ASan report in all three compilers; benign control is clean on both
tags. Caller reaches the sink through public decoder APIs only; no synthetic
consumer.

## Rung-4 feasibility and cheapest next step

The write is a 16-bit `SliceHeaderIndex`, attacker-influenced but not
arbitrary bytes; ASan's 2-byte-overrun lands in redzone, not a proven adjacent
object. A rung-4 claim needs a plain-allocator layout measurement showing the
overflow reaches a named adjacent field (the advisory's Valgrind trace shows a
neighbouring `de265_progress_lock` allocation) and chosen values observed
there. The cheapest next experiment: compile the plain v1.0.16 build with a
gdb watch on the `ctb_info` buffer end, run the same 254-byte input, and record
the exact adjacent allocation and the written value; if it is not a pointer or
length field, stay at rung 4 PARTIAL. No wire/request path was found: the
public decoder API takes in-memory bitstreams; an application that feeds it
from a request would be a separate consumer, not this library's boundary.

## Negatives preserved

- An initial autotools build path failed on v1.0.17 because that tag ships no
  `autogen.sh` (CMake-only); runner uses CMake for both tags.
- An initial C++-driver link of `poc.c` failed (implicit `malloc` cast, goto
  across initialization); the runner links with the C compiler plus
  `-lstdc++`, matching the advisory recipe.
- Advisory reports further Valgrind OOB reads during deblocking after the
  write; those are not treated as the write primitive.

## Witness receipt (2026-11-26 07:5xZ, W254)

Independent replay of the unmodified `run-all.sh` from a clean
`git archive 8b4caaf9`, with three inputs re-fetched independently, gave
`RESULT PASS=12 FAIL=0` rc 0. Both vulnerable ASan traces match the frames
quoted above verbatim; fixed/benign controls are clean, plain vulnerable is
silent. Extra benign inputs were clean on the same ASan binary. Verdict:
ESTABLISHED AS LABELED at rung 3 verbatim / rung 4 PARTIAL, no contradiction,
no grade change, NO r5. Detail:
`.mishe-tauftauf/artifacts/witness-w254-libde265shell/detail.md`.
