# libxml22shell — admitted status (2026-11-26 01:4xZ)

**ADMITTED 01:4xZ by the operator under standing #6 as the 154th declared
target mind.** Window 162 was already live and was adopted, not duplicated.
No hy4-flash route, resolver key or generated wake unit was added: those and
the full-flag sync remain person-reserved. Brief:
`reports/frontier-libxml22shell.md`. Evidence and hashes:
`lab/frontier/libxml22shell/PROVENANCE.md`.

Claim: `CVE-2026-86138` (MITRE, CWE-190, CVSS 3.1 6.9), libxml2 before
2.15.4, fix commit `a4cba4b5b5a8c42e155ed42d2d2a44955465a2e4`. A 32-bit
`namelen + plen + 1` wrap in `xmlDictAddQString()` under-allocates the string
pool before the prefix/name `memcpy`.

Local result: verbatim pinned function bodies from v2.15.3 and v2.15.4;
GCC + Clang ASan `WRITE of size 4294967280`, 0 bytes after a 1048-byte region
in `xmlDictAddQString`; safe input clean in both; plain build shows chosen
`MISHE-LIBXML2!!` bytes at the first byte past the pool.
`run-all.sh`: 26 PASS / 0 FAIL, rc 0.

Negative preserved: v2.15.4 (and byte-identical master) still overflow on the
wrap-to-zero input because the fix's outer condition keeps the wrapping
32-bit expression. The fix does reject the wrap-to-1000 input, which is the
usable fixed control. This contradicts the advisory's blanket "fixed in
2.15.4" statement for one concrete input; it does not establish impact beyond
what is measured.

Grade: rung 3 pinned verbatim / rung 4 PARTIAL chosen bytes past the pool in
a synthetic canary. No real library, no XML wire input, no pointer, no
command, no r5.

Witness (W236, 2026-11-26 00:23Z): **ESTABLISHED AS LABELED**, no
contradiction, no grade change, no r5. Clean `git archive b058f2a8`
replay, unmodified `run-witness.sh` sha256
`261a0074ea245d45e631b614a7b3079c32b3fe0c51befe0909698354269afd6e`,
26 PASS / 0 FAIL, rc 0, four pins exact. Independently verified the excerpts
are byte-exact (`sed -n 196,245p` / `196,256p` reproduce the pinned hashes),
the ASan WRITE at `dict-vulnerable.inc:45` / alloc at `:30`, the
`v2.15.4`/wrap-to-zero overflow at `dict-fixed.inc:56`, the wrap-to-1000
`RET=NULL` control, and the plain canary `MISHE-LIBXML2!!` at
`g_arena[POOL_BYTES]` from `harness/driver.c:130/:146`.
Next experiment for the mind: build real libxml2 v2.15.3 and test whether a
post-pool write overlaps a live dictionary object and whether a parser can
supply a ~2^32-byte name. Grade stays rung 3 / rung 4 PARTIAL until that is
measured; no r5 claim.
