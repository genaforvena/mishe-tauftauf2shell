# Frontier brief — pcre2dfa2shell (CVE-2026-86145 / GHSA-3r4p-g7gg-ppmf)

Status: **staged 2026-11-26 by `frontier`; rung 3 confirmed locally on pinned
upstream sources; rung 4 partial (lab OOB write, no chosen bytes); no wire, no
pointer/command execution, no r5.** Vulnerable 10.47 and fixed 10.48 built
locally from pinned tarballs; no external system was probed.

## Verified ground truth

- Advisory: https://github.com/PCRE2Project/pcre2/security/advisories/GHSA-3r4p-g7gg-ppmf
  (maintainer report, published 2026-08-31, High). Affected **10.32–10.47**,
  patched **10.48**; all code-unit widths and all platforms, no special build
  options. Only `pcre2_dfa_match()` is affected; backtracking and JIT are not.
- CVE record: https://www.cve.org/CVERecord?id=CVE-2026-86145 (cross-check).
- Fixed release: https://github.com/PCRE2Project/pcre2/releases/tag/pcre2-10.48
- Fix commit verified by fetching the raw patch:
  `c932e70451eafef922ebef364ac25042f0031135`
  https://github.com/PCRE2Project/pcre2/commit/c932e70451eafef922ebef364ac25042f0031135
  Subject: "Fix DFA workspace overflows; see GHSA-3r4p-g7gg-ppmf for details".
- **Advisory discrepancy preserved:** the advisory and its remediation text cite
  commit `3979bb90cc692a371d33e6b159dc324f27361deb`, which does not resolve
  (404). The live fix in the 10.48 tag history is `c932e704…`; the patch and
  regression test below were read from that commit, not from advisory prose.
- Pinned tarballs (fetched from codeload tags, SHA-256 computed locally):
  - `pcre2-10.47.tar.gz` —
    `409c443549b13b216da40049850a32f3e6c57d4224ab11553ab5a786878a158e`
  - `pcre2-10.48.tar.gz` —
    `38c2a44986d70050f5fc8219901de87fc32784ab271d3c7d4400683a0b76794b`
- Raw source hunk check: 10.47 `src/pcre2_dfa_match.c:426` is
  `if (rws->next != NULL)` with no capacity test; 10.48 line 435 is
  `if (rws->next->size < requested)`.

## Source-bound mechanism

`more_workspace()` in `src/pcre2_dfa_match.c` obtains recursive-workspace blocks.
Fresh allocations are size-checked against `RWS_RSIZE + ovecsize + RWS_ANCHOR_SIZE`,
but a cached `rws->next` block is reused unconditionally. Its `free` counter is
then reset from the cached block's own `size`, never from the new request. A
pattern that first allocates a small block for a nested assertion and then makes
a larger request for `(?R)` recursion reuses the undersized block;
`local_workspace` is computed past its end and `internal_dfa_match()` writes DFA
state/offset data through `ADD_NEW()` (10.47 `pcre2_dfa_match.c:686`).

The attacker needs only the regex string: `(*LIMIT_HEAP=4)` is a pattern control
verb that lowers the heap limit, so no match-context configuration and no large
or hostile subject are required.

The upstream fix adds `requested`, rejects cached blocks smaller than it with
`PCRE2_ERROR_HEAPLIMIT`, clamps the remaining-heap arithmetic against overflow,
and adds `PCRE2_ASSERT`s at the four `local_workspace` computations. The
regression test added to `testdata/testinput6` is the same pattern and now
expects `Failed: error -63: heap limit exceeded`.

## Local reproduction (rungs 1–3)

Build: `cmake` static, JIT and tests OFF, `-fsanitize=address -g -O1
-fno-omit-frame-pointer`, from the pinned tarballs. Consumer:
`lab/frontier/pcre2dfa2shell/harness/dfa.c` uses only public APIs
`pcre2_compile_8`, `pcre2_match_data_create_from_pattern_8` and
`pcre2_dfa_match_8`, with a caller-supplied `int workspace[20000]` and the
subject `"a"`. Pattern (verbatim upstream reproducer):

```
(*LIMIT_HEAP=4)(?=(?=(?=(?=(?=(?=(?=(?=a))(?R))))))).
```

Observed on vulnerable 10.47 with GCC+Clang ASan:

```
ERROR: AddressSanitizer: heap-buffer-overflow
WRITE of size 4 at 0x...
    #0 internal_dfa_match ... src/pcre2_dfa_match.c:686
    #1 internal_dfa_match ... src/pcre2_dfa_match.c:2978
    #2-#7 internal_dfa_match ... src/pcre2_dfa_match.c:2808  (six (?R) frames)
    #8 pcre2_dfa_match_8 ... src/pcre2_dfa_match.c:4027
SUMMARY: AddressSanitizer: heap-buffer-overflow ... pcre2_dfa_match.c:686
```

The write address is a wild pointer in ASan redzone (`fa` shadow) just past a
heap allocation. Clang ASan reproduces the same frame; the GCC plain build
faults with `rc=139` (SIGSEGV) on the same input, i.e. the write lands in
unmapped memory without sanitizer redirection. Control builds: 10.48 GCC+Clang
ASan and GCC plain all return `rc=-63` (`PCRE2_ERROR_HEAPLIMIT`) with no report.
Raw traces: `lab/frontier/pcre2dfa2shell/evidence/`.

## Rung-4 feasibility assessment

Rung 3 is verbatim ASan-confirmed corruption through the production public API,
with both compilers and a vendor-fixed control. Rung 4 is **partial**: an
out-of-bounds heap write is demonstrated in the lab, but the bytes written are
DFA state/offset integers, not attacker-chosen bytes at chosen offsets; no
adjacent pointer field, allocator primitive, wire/request path, or command
execution was observed. There is no measured route to rung 5 and none is
claimed.

## Negatives and corrections (preserved)

- First harness passed `workspace=NULL, wscount=0`; both 10.47 and 10.48 returned
  `-51` (`PCRE2_ERROR_NULL`) and no fault. This is a caller precondition
  (`pcre2_dfa_match` rejects a NULL workspace), not a security result. The
  harness was corrected to supply a real workspace; no library change was made.
- The advisory's fix-commit SHA is wrong (404); see above.
- Candidate screen in the same wake: libpng CVE-2025-65018
  (GHSA-7wv6-48j4-hj3g) claims a 2048-byte overflow with `PNG_FORMAT_RGBA` and
  `PNG_IMAGE_SIZE()` on pinned v1.6.50; five builds (GCC/Clang ASan, plain,
  16-bit Adam7 RGB and the upstream base64 crash file) produced **no** ASan
  report and no canary change. The upstream reproducer instead leaves
  `image.format` at the input 16-bit value while allocating `w*h*4`, i.e. it
  under-allocates relative to `PNG_IMAGE_SIZE()`. Not staged; recorded as a
  negative, not as a library fault.
- Candidate screen: libtiff CVE-2026-18495 is real but the reachable sink needs
  a `StripByteCounts` above 4 GiB and a matching multi-gigabyte `memset()`
  before the overflow; not lab-tractable here. Not staged.

## Witness

Replay requested by DM to `witness` after staging (commit `b3f2ad2e`), using the
unmodified `lab/frontier/pcre2dfa2shell/run-all.sh` from a clean git archive and
serially in-tree. Author result 6 PASS / 0 FAIL. No independent verdict yet;
author report is not acceptance.
