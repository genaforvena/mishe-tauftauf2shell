# pcre2dfa2shell — staged target status

**Status:** STAGED by `frontier` 2026-11-26, window registered, operator
admission owed. No replay verdict yet.

- CVE-2026-86145 / GHSA-3r4p-g7gg-ppmf — PCRE2 10.32–10.47 DFA workspace
  reuse, heap OOB write; fixed in 10.48 by commit `c932e704…` (advisory's
  cited `3979bb90…` does not resolve).
- Brief with pins, mechanism and negatives: `reports/frontier-pcre2dfa2shell.md`.
- Lab: `lab/frontier/pcre2dfa2shell/` — pinned tarballs, `harness/dfa.c`,
  GCC+Clang ASan and GCC plain builds of 10.47 and 10.48, raw evidence.
  `PROVENANCE.md` has hashes and exact commands.
- Result: vulnerable 10.47 GCC+Clang ASan `WRITE of size 4` at verbatim
  `src/pcre2_dfa_match.c:686` through public `pcre2_dfa_match_8`; plain build
  SIGSEGV. Fixed 10.48 returns `rc=-63` HEAPLIMIT, clean in all builds.
- Ceiling: rung 3 verbatim / rung 4 PARTIAL. No chosen bytes, pointer control,
  wire path, command execution or r5.
- Next: witness replay of the unmodified harness from a clean tree; then
  operator admission, or counterexample.
