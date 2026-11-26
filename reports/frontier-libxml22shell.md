# Frontier brief: libxml2 xmlDictAddQString 32-bit sum overflow — CVE-2026-86138

Status: **STAGED 2026-11-26 by frontier W236**, awaiting operator admission
and witness replay. Rung 3 pinned verbatim function; rung 4 PARTIAL (chosen
bytes observed past the pool in a synthetic adjacent canary of a live plain
process). No real library build, no XML wire input, no pointer control, no
command execution and no rung 5. An important negative is preserved: the
published v2.15.4 fix does **not** stop the wrap-to-zero input.

## Claim and scope

- CVE-2026-86138, CNA MITRE, published 2026-09-05, CWE-190 with resultant
  heap buffer overflow, CVSS 3.1 6.9 (AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:L).
  Source: `https://www.cve.org/CVERecord?id=CVE-2026-86138`.
- Project: GNOME libxml2, `dict.c`, `xmlDictAddQString()`. Affected: before
  2.15.4. Fix commit `a4cba4b5b5a8c42e155ed42d2d2a44955465a2e4`
  ("fix: add overflow checks to xmlDictAddQString in dict.c", 2026-04-16).
  Pinned vulnerable tag `v2.15.3`, pinned fixed tag `v2.15.4`.
- Claimed primitive: `namelen + plen + 1` is computed in `unsigned int`; it
  wraps, so `4 * (wrapped)` under-allocates the dictionary string pool and the
  following `memcpy` of prefix and name writes past the allocation.
- The caller boundary is a claim from the CVE description; no live parser,
  XML document or socket is exercised in this staged evidence.

## Pins and source-bound mechanism

- Byte-exact pins: `pins/dict-v2.15.3.c` (SHA-256
  `416253664eb3d95a393be6c61c649a1b5600729bbd1e3ce9123df08b12d8f388`) and
  `pins/dict-v2.15.4.c`
  (`2663392f29dd45eb7ad802c471e146d4f6f509e317a4938b496920b4ea0228b4`).
  Verbatim function excerpts: `pins/dict-vulnerable.inc` = v2.15.3 `dict.c`
  lines 196-245 (`c2a4a0ed9ffe8fabffc9f0e19de8c3d1ca59fee80dc68f454211ad511a7f0d9a`),
  `pins/dict-fixed.inc` = v2.15.4 lines 196-256
  (`035611cca31f6bdb67b030c221c8fb7445750d841479e6f4f2a7e8874c28b9d4`).
  Upstream `master` `dict.c` is byte-identical to v2.15.4 (same SHA-256).
- Vulnerable body, lines 221-224 of `dict.c`:
  `if (size == 0) size = 1000; else size *= 4;` then
  `if (size < 4 * (namelen + plen + 1)) size = 4 * (namelen + plen + 1);`.
  With `plen=15`, `namelen=0xfffffff0`, the 32-bit sum wraps to 0, so the
  guard is false and `size` stays 1000. `xmlMalloc(sizeof(xmlDictStrings) +
  size)` returns a 1048-byte pool (sizeof struct 48, `array` at offset 40,
  1000 array bytes, 8 bytes tail padding). `memcpy(prefix,plen)`, the `:`
  store and `memcpy(name,namelen)` then write 4294967280 bytes from that
  address.
- Fix hunk from commit `a4cba4b5` replaces the growth/guard block with
  `SIZE_MAX`-based checks and a `(size_t) namelen + plen + 1` cast. The
  **outer** condition remains `if (size / 4 < namelen + plen + 1)`, whose
  right operand still wraps to 0. For the wrap-to-zero input the inner
  corrected branch is never reached, so v2.15.4 and master still overflow.
  For `plen=1000`, `namelen=0xffffffff` (sum wraps to 1000, true sum
  2^32+1000), `250 < 1000` is true and the fixed build computes a ~17 GiB
  allocation, which the harness allocator cap refuses, returning NULL.
- This is a source-bound contradiction to the advisory's "fixed in 2.15.4"
  claim for one concrete input, not a claim that the whole fix is useless.

## Local evidence

`bash lab/frontier/libxml22shell/run-all.sh`: **26 PASS / 0 FAIL**, rc 0.
GCC and Clang ASan on the verbatim vulnerable body: `heap-buffer-overflow`,
`WRITE of size 4294967280`, `0 bytes after 1048-byte region`, stack
`#2 xmlDictAddQString (pins/dict-vulnerable.inc:45)`, allocation at
`pins/dict-vulnerable.inc:30` via the stand-in `xmlMalloc`.
Negative: GCC ASan on the pinned v2.15.4 body with the same wrap-to-zero input
reports the identical overflow. Fixed control: v2.15.4 body rejects the
wrap-to-1000 input (`RET=NULL`, ASan-clean) while the vulnerable body reports
an overflow on that input. Safe input (`plen=15`, `namelen=16`) is ASan-clean
and returns non-NULL in both bodies. Plain vulnerable build with a sparse
2^32 read-only source and a 64-byte canary immediately after the pool:
`SIGSEGV_CAUGHT=1`,
`CANARY_AFTER=4d495348452d4c4942584d4c32212100` — the chosen
`MISHE-LIBXML2!!` bytes land at the first byte past the allocation. The source
is an anonymous sparse mapping; only the touched pages are resident.
Harness stand-ins: struct definitions, constrained allocator (1 GiB cap),
caller and SIGSEGV readback. The two function bodies are included verbatim.
Exact hashes, commands and raw logs are in `PROVENANCE.md`.

## Grade and tractability

- **Rung 3:** GCC and Clang ASan-confirmed heap OOB WRITE in the verbatim
  pinned `xmlDictAddQString()`, with safe-input and (for wrap-1000) fixed
  controls; the wrap-0 fixed-build failure is preserved as a negative.
- **Rung 4 PARTIAL:** the written bytes are chosen in the harness and observed
  past the allocation in a live plain process; the write offset is fixed by
  the struct layout, not chosen by the input. No adjacent live object, no
  pointer-bearing target and no XML-derived bytes.
- **Not rung 5:** no real libxml2 build, no XML document, no parser API, no
  loopback socket, no attacker control of the value, no pointer hijack, no
  command and no observed side effect.

Cheapest next experiment: build real libxml2 v2.15.3 without sanitizers,
call `xmlDictCreateSub`/`xmlDictAddQString` through `xmlDictAddQName` with a
synthetic 2^32-byte name, and check whether the post-pool bytes overlap a live
`xmlDictEntry` or `xmlDictStrings` object; then determine whether a real XML
parser can be made to supply a name near 2^32 bytes. Preserve the no-wire,
no-pointer and no-command ceiling until measured.

## Duplicate check

`reports/frontier-*.md` and the wall's do-not-duplicate list were checked
before provisioning: libxml2 appears only as a dependency of apache2shell,
php2shell, mapserver2shell and other admitted targets; there is no libxml2
frontier brief, lab, window or admitted mind. The 2026-11-25 libxml2 UAF/NUL
advisories (CVE-2026-137067/137068/137075) are distinct bugs and were not
used.
