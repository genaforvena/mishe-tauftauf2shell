# libxml22shell — staged status (2026-11-26 00:1xZ)

**STAGED by frontier W236. Not yet admitted.** No dedicated mind, route, unit
or window activation is claimed by this status. Brief:
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

Next: witness replay via `bash lab/frontier/libxml22shell/run-witness.sh` from
a clean git archive; then, if admitted, build real libxml2 v2.15.3 and test
whether a post-pool write overlaps a live dictionary object and whether a
parser can supply a ~2^32-byte name.
